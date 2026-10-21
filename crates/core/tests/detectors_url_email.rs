//! SR-003 URL credentials and SR-005 email addresses, including their disambiguation.
mod common;
use common::*;
use spymonk_redact_core::Options;

#[test]
fn sr003_url_credentials_any_scheme() {
    check_all(
        Options::default(),
        &[
            (
                "postgresql://app:fake-pass@db/app",
                "postgresql://app:[REDACTED]@db/app",
            ),
            (
                "postgresql://app:fake-pass@db.example/app",
                "postgresql://app:[REDACTED]@db.example/app",
            ),
            (
                "jdbc:mysql://root:fake@10.0.0.5:3306/x",
                "jdbc:mysql://root:[REDACTED]@10.0.0.5:3306/x",
            ),
            (
                "redis://:secretpw@cache:6379/0",
                "redis://:[REDACTED]@cache:6379/0",
            ),
            ("amqp://u:p@ss@mq/", "amqp://u:[REDACTED]@mq/"),
            (
                "http://u:pw@[fd00::1]:80/",
                "http://u:[REDACTED]@[fd00::1]:80/",
            ),
            (
                "remote: https://user:fake@git.example/r.git",
                "remote: https://user:[REDACTED]@git.example/r.git",
            ),
            (
                "see \"mongodb+srv://u:p%40ss@c0.example.net/db\"",
                "see \"mongodb+srv://u:[REDACTED]@c0.example.net/db\"",
            ),
            (
                "https://x/?next=https://a:b@h/",
                "https://x/?next=https://a:[REDACTED]@h/",
            ),
        ],
    );
    unchanged_all(
        Options::default(),
        &[
            "https://user@host/path",
            "https://host:8443/path",
            "https://a:b/c@d",
            "x://",
        ],
    );
    attributed(
        "postgresql://app:fake-pass@db/app",
        "postgresql://app:[REDACTED]@db/app",
        "SR-003",
        1,
    );
}

#[test]
fn sr005_email_grammar() {
    check_all(
        Options::default(),
        &[
            ("user=alex@example.com", "user=[EMAIL REDACTED]"),
            ("mail alex@example.com.", "mail [EMAIL REDACTED]."),
            ("<alex.k+tag@mail.example.co.uk>", "<[EMAIL REDACTED]>"),
            (
                "GET /?email=alex@example.com&x=1",
                "GET /?email=[EMAIL REDACTED]&x=1",
            ),
            ("a@b.io,c@d.io", "[EMAIL REDACTED],[EMAIL REDACTED]"),
        ],
    );
    unchanged_all(
        Options::default(),
        &[
            "alex@localhost",
            "user@host/path",
            "a..b@example.com",
            "x@y@example.com",
            "alex@example.c0m",
            "@example.com",
            "alex@-bad.com",
        ],
    );
}

#[test]
fn sr005_respects_option() {
    unchanged_all(EMAIL_OFF, &["user=alex@example.com"]);
}

#[test]
fn email_inside_url_authority_only_in_username() {
    check_all(
        Options::default(),
        &[(
            "https://alex@example.com:pw@host/",
            "https://[EMAIL REDACTED]:[REDACTED]@host/",
        )],
    );
    check_all(
        EMAIL_OFF,
        &[(
            "https://alex@example.com:pw@host/",
            "https://alex@example.com:[REDACTED]@host/",
        )],
    );
}

#[test]
fn secret_value_wins_over_email() {
    attributed(
        "password=alex@example.com",
        "password=[REDACTED]",
        "SR-001",
        1,
    );
}

#[test]
fn email_never_overlaps_a_url_scheme() {
    let input = "a@b.com://x/y";
    let once = redact(input);
    assert_eq!(redact(&once), once, "second run changed {once:?}");
}

#[test]
fn placeholder_inside_url_does_not_end_it_on_a_second_pass() {
    let input = "\"\"postgres://app:pw@db/x🙂alex@example.com=C:\\Users\\alex\\";
    let once = redact(input);
    assert_eq!(redact(&once), once);
}

#[test]
fn malformed_authority_does_not_hide_a_home_path() {
    let input = "Authorization: Bearer https://,/home/alex/";
    let once = redact(input);
    assert_eq!(once, "Authorization: Bearer [REDACTED],/home/[USER]/");
    assert_eq!(redact(&once), once);
}

/// RFC 3986 allows `;` (a sub-delimiter) in user information, so it cannot end a URL.
#[test]
fn sr003_password_with_semicolon() {
    check_all(
        Options::default(),
        &[(
            "https://user:pa;ss@host.example/x",
            "https://user:[REDACTED]@host.example/x",
        )],
    );
}
