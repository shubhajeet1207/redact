//! TRD §9.3, §19.6: atomic output, same-file refusal, and non-regular targets.
mod common;
use common::*;

use std::path::Path;

fn write(path: &Path, text: &str) {
    std::fs::write(path, text).expect("write");
}

#[test]
fn output_file_is_written_and_stdout_stays_empty() {
    let dir = temp_dir("out-ok");
    let out = dir.join("clean.log");
    let r = run(
        ["--output", out.to_str().expect("utf8")],
        b"password=CANARYcli1\n",
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(r.stdout.is_empty());
    assert_eq!(
        std::fs::read(&out).expect("output"),
        b"password=[REDACTED]\n"
    );
    assert_eq!(entries(&dir), ["clean.log"], "no temporary file is left");
}

#[test]
fn an_existing_target_is_replaced_on_success_and_untouched_on_failure() {
    let dir = temp_dir("out-replace");
    let out = dir.join("clean.log");
    write(&out, "previous\n");
    let r = run(["-o", out.to_str().expect("utf8")], b"token=CANARYcli1\n");
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(std::fs::read(&out).expect("read"), b"token=[REDACTED]\n");

    write(&out, "previous\n");
    let r = run(["-o", out.to_str().expect("utf8")], b"ok\nbad \xff\n");
    assert_eq!(r.code, 1);
    assert!(r.stdout.is_empty());
    assert_eq!(std::fs::read(&out).expect("read"), b"previous\n");
    assert_eq!(entries(&dir), ["clean.log"]);
}

#[test]
fn a_failed_run_leaves_no_file_at_a_new_target() {
    let dir = temp_dir("out-none");
    let out = dir.join("clean.log");
    let r = run(
        [
            "--max-line-bytes",
            "1024",
            "-o",
            out.to_str().expect("utf8"),
        ],
        "x".repeat(2000).as_bytes(),
    );
    assert_eq!(r.code, 1);
    assert!(entries(&dir).is_empty(), "{:?}", entries(&dir));
}

#[test]
fn the_input_file_is_refused_as_output_under_any_spelling() {
    let dir = temp_dir("same");
    std::fs::create_dir(dir.join("sub")).expect("sub");
    let input = dir.join("in.log");
    write(&input, "password=CANARYcli1\n");
    let link = dir.join("hard.log");
    std::fs::hard_link(&input, &link).expect("hard link");
    for target in [
        input.clone(),
        dir.join(".").join("in.log"),
        dir.join("sub").join("..").join("in.log"),
        link,
    ] {
        let r = run([input.as_os_str(), "-o".as_ref(), target.as_os_str()], b"");
        assert_eq!(r.code, 1, "{}: {}", target.display(), r.stderr);
        assert!(r.stderr.contains("OUTPUT_IS_INPUT"), "{}", r.stderr);
        assert!(
            !r.stderr.contains("in.log"),
            "no path in messages: {}",
            r.stderr
        );
    }
    assert_eq!(
        std::fs::read(&input).expect("read"),
        b"password=CANARYcli1\n"
    );
}

#[test]
fn stdin_redirected_from_the_target_is_refused() {
    let dir = temp_dir("same-stdin");
    let input = dir.join("in.log");
    write(&input, "password=CANARYcli1\n");
    let out = bin()
        .args(["-o", input.to_str().expect("utf8")])
        .stdin(std::fs::File::open(&input).expect("open"))
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("OUTPUT_IS_INPUT"));
    assert_eq!(
        std::fs::read(&input).expect("read"),
        b"password=CANARYcli1\n"
    );
}

#[test]
fn a_directory_target_is_not_regular() {
    let dir = temp_dir("out-dir");
    let target = dir.join("target");
    std::fs::create_dir(&target).expect("dir");
    let r = run(["-o", target.to_str().expect("utf8")], b"x\n");
    assert_eq!(r.code, 1);
    assert!(r.stderr.contains("OUTPUT_NOT_REGULAR"), "{}", r.stderr);
}

#[cfg(unix)]
#[test]
fn symbolic_link_targets_are_refused() {
    let dir = temp_dir("out-link");
    let input = dir.join("in.log");
    write(&input, "x\n");
    let elsewhere = dir.join("elsewhere.log");
    write(&elsewhere, "keep\n");
    let link = dir.join("link.log");
    std::os::unix::fs::symlink(&elsewhere, &link).expect("symlink");
    let r = run(["-o", link.to_str().expect("utf8")], b"x\n");
    assert!(r.stderr.contains("OUTPUT_NOT_REGULAR"), "{}", r.stderr);
    assert_eq!(std::fs::read(&elsewhere).expect("read"), b"keep\n");

    let to_input = dir.join("to-input.log");
    std::os::unix::fs::symlink(&input, &to_input).expect("symlink");
    let r = run(
        [input.as_os_str(), "-o".as_ref(), to_input.as_os_str()],
        b"",
    );
    assert!(r.stderr.contains("OUTPUT_IS_INPUT"), "{}", r.stderr);
}

#[cfg(unix)]
#[test]
fn new_output_files_are_private() {
    use std::os::unix::fs::PermissionsExt;
    let dir = temp_dir("out-mode");
    let out = dir.join("clean.log");
    assert_eq!(run(["-o", out.to_str().expect("utf8")], b"x\n").code, 0);
    let mode = std::fs::metadata(&out).expect("meta").permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
}

#[test]
fn a_missing_directory_fails_to_write() {
    let dir = temp_dir("out-missing");
    let out = dir.join("no-such-dir").join("clean.log");
    let r = run(["-o", out.to_str().expect("utf8")], b"x\n");
    assert_eq!(r.code, 1);
    assert!(r.stderr.contains("OUTPUT_WRITE_FAILED"), "{}", r.stderr);
}

#[test]
fn output_and_report_file_must_differ() {
    let r = run(["-o", "same.json", "--report-file", "same.json"], b"x\n");
    assert_eq!(r.code, 2);
}
