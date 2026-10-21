//! SR-004 usernames in home-directory paths.
mod common;
use common::*;
use spymonk_redact_core::Options;

#[test]
fn sr004_posix_and_macos() {
    check_all(
        Options::default(),
        &[
            ("/home/alex/app/config.yml", "/home/[USER]/app/config.yml"),
            ("HOME=/home/alex", "HOME=/home/[USER]"),
            ("/Users/alex/Library/Logs", "/Users/[USER]/Library/Logs"),
            ("/var/home/alex/x", "/var/home/[USER]/x"),
            ("/mnt/c/Users/alex/x", "/mnt/c/Users/[USER]/x"),
            (
                "PATH=/home/alex/bin:/usr/bin",
                "PATH=/home/[USER]/bin:/usr/bin",
            ),
            ("at (/home/a.b-c_d/x.py:12)", "at (/home/[USER]/x.py:12)"),
            (
                "file:///home/alex/notes.txt",
                "file:///home/[USER]/notes.txt",
            ),
            ("\"/home/John Smith/x\"", "\"/home/[USER]/x\""),
            ("open('/Users/Zoë Ng/a')", "open('/Users/[USER]/a')"),
        ],
    );
}

#[test]
fn sr004_windows_forms() {
    check_all(
        Options::default(),
        &[
            ("C:\\Users\\alex\\app.log", "C:\\Users\\[USER]\\app.log"),
            ("c:\\users\\alex\\", "c:\\users\\[USER]\\"),
            ("C:/Users/alex/x", "C:/Users/[USER]/x"),
            (
                "{\"p\":\"C:\\\\Users\\\\alex\\\\app\"}",
                "{\"p\":\"C:\\\\Users\\\\[USER]\\\\app\"}",
            ),
            (
                "USERPROFILE=C:\\Users\\alex",
                "USERPROFILE=C:\\Users\\[USER]",
            ),
            ("\"D:\\Users\\Ann Lee\\f\"", "\"D:\\Users\\[USER]\\f\""),
        ],
    );
}

#[test]
fn sr004_non_targets() {
    unchanged_all(
        Options::default(),
        &[
            "see https://example.com/home/about/",
            "/home/1001/",
            "/home//x",
            "/home/",
            "C:\\Users\\",
            "AB:\\Users\\alex\\",
            "/homes/alex/",
        ],
    );
    attributed(
        "/home/alex/app/config.yml",
        "/home/[USER]/app/config.yml",
        "SR-004",
        1,
    );
}

#[test]
fn never_redacts_into_a_url_scheme() {
    // Regression from the idempotence property: redacting `postgres` destroyed the URL.
    let input = "/Users/postgres://app:pw@db/x/home/alex/";
    let once = redact(input);
    assert_eq!(once, "/Users/postgres://app:[REDACTED]@db/x/home/alex/");
    assert_eq!(redact(&once), once);
}
