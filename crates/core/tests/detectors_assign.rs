//! SR-001 named secret values, SR-002 authorization credentials, SR-009 cookie values.
mod common;
use common::*;
use spymonk_redact_core::Options;

#[test]
fn sr001_separators_and_quoting() {
    check_all(
        Options::default(),
        &[
            ("password=fake-value", "password=[REDACTED]"),
            ("password = hunter2 rest", "password = [REDACTED] rest"),
            ("password: hunter2", "password: [REDACTED]"),
            ("password:hunter2", "password:[REDACTED]"),
            ("{\"api_key\":\"fake-key\"}", "{\"api_key\":\"[REDACTED]\"}"),
            ("'secret': 'x y'", "'secret': '[REDACTED]'"),
            ("\"password\" => \"x\"", "\"password\" => \"[REDACTED]\""),
            ("token := abc", "token := [REDACTED]"),
            (
                "\"password\": \"a\\\"b\" ok",
                "\"password\": \"[REDACTED]\" ok",
            ),
            ("password=\"abc def", "password=\"[REDACTED]"),
            ("\tpasswd=x\t", "\tpasswd=[REDACTED]\t"),
        ],
    );
}

#[test]
fn sr001_compound_and_camel_keys() {
    check_all(
        Options::default(),
        &[
            ("export GITHUB_TOKEN=fake", "export GITHUB_TOKEN=[REDACTED]"),
            ("DB_PASSWORD=fake", "DB_PASSWORD=[REDACTED]"),
            (
                "\"clientSecret\": \"fake\"",
                "\"clientSecret\": \"[REDACTED]\"",
            ),
            ("apiKey=abc", "apiKey=[REDACTED]"),
            ("APIKey=abc", "APIKey=[REDACTED]"),
            ("x-api-key: abc", "x-api-key: [REDACTED]"),
            (
                "aws_secret_access_key = abc",
                "aws_secret_access_key = [REDACTED]",
            ),
            ("accessToken=abc", "accessToken=[REDACTED]"),
            (
                "DefaultEndpointsProtocol=https;AccountName=x;AccountKey=abc==;",
                "DefaultEndpointsProtocol=https;AccountName=x;AccountKey=[REDACTED];",
            ),
            (
                "Server=db;Password=x;User=y",
                "Server=db;Password=[REDACTED];User=y",
            ),
            (
                "GET /cb?access_token=abc&x=1",
                "GET /cb?access_token=[REDACTED]&x=1",
            ),
            ("-Ddb.password=x", "-Ddb.password=[REDACTED]"),
            ("🙂password=x", "🙂password=[REDACTED]"),
        ],
    );
}

#[test]
fn sr001_flag_form() {
    check_all(
        Options::default(),
        &[
            (
                "--password fake --verbose",
                "--password [REDACTED] --verbose",
            ),
            ("mysql --password=fake db", "mysql --password=[REDACTED] db"),
            ("cli --client-secret x", "cli --client-secret [REDACTED]"),
            ("cli \"--token\" \"abc\"", "cli \"--token\" \"[REDACTED]\""),
        ],
    );
    unchanged_all(
        Options::default(),
        &["--password --verbose", "--password", "--token-file path"],
    );
}

#[test]
fn sr001_non_targets_and_skip_values() {
    unchanged_all(
        Options::default(),
        &[
            "password_length=16",
            "token_type=Bearer max_tokens=10",
            "passwordHint=abc",
            "secret_name=prod",
            "mypassword=x",
            "password=null",
            "token: true",
            "\"password\": null",
            "password=",
            "\"password\": \"\"",
            "if password == other",
            "password != x",
            "tokens: [a, b]",
            "credentials: {",
        ],
    );
    check_all(
        Options::default(),
        &[("\"password\": \"null\"", "\"password\": \"[REDACTED]\"")],
    );
}

#[test]
fn sr001_delimiters_and_placeholders() {
    check_all(
        Options::default(),
        &[
            ("password=abc,user=bob", "password=[REDACTED],user=bob"),
            ("password=abc#123 ok", "password=[REDACTED] ok"),
            ("(password=abc)", "(password=[REDACTED])"),
        ],
    );
    unchanged_all(
        Options::default(),
        &[
            "password=[REDACTED]",
            "password=[EMAIL REDACTED] x",
            "\"token\": \"[REDACTED]\"",
        ],
    );
}

#[test]
fn sr001_ansi_colored_keys_and_values() {
    check_all(
        Options::default(),
        &[
            (
                "\u{1b}[31mtoken=abc\u{1b}[0m",
                "\u{1b}[31mtoken=[REDACTED]\u{1b}[0m",
            ),
            (
                "\u{1b}[1;33mDB_PASSWORD\u{1b}[0m=abc",
                "\u{1b}[1;33mDB_PASSWORD\u{1b}[0m=[REDACTED]",
            ),
            ("password=abc\u{7}rest", "password=[REDACTED]\u{7}rest"),
        ],
    );
}

#[test]
fn sr002_placeholder_does_not_hide_rest_of_line() {
    check_all(
        Options::default(),
        &[(
            "Authorization: Bearer [REDACTED] password=abc",
            "Authorization: Bearer [REDACTED] password=[REDACTED]",
        )],
    );
}

#[test]
fn sr001_counts_each_occurrence() {
    attributed(
        "password=a password=a",
        "password=[REDACTED] password=[REDACTED]",
        "SR-001",
        2,
    );
}

#[test]
fn sr002_authorization() {
    check_all(
        Options::default(),
        &[
            (
                "Authorization: Bearer fake-token",
                "Authorization: Bearer [REDACTED]",
            ),
            (
                "\"authorization\": \"Basic ZmFrZTpmYWtl\"",
                "\"authorization\": \"Basic [REDACTED]\"",
            ),
            (
                "Authorization: Basic dXNlcjpwYXNz==",
                "Authorization: Basic [REDACTED]",
            ),
            (
                "Proxy-Authorization: Bearer abc",
                "Proxy-Authorization: Bearer [REDACTED]",
            ),
            (
                "Authorization: Digest username=\"a\", response=\"b\"",
                "Authorization: Digest [REDACTED]",
            ),
            (
                "Authorization: AWS4-HMAC-SHA256 Credential=K/x, Signature=abc",
                "Authorization: AWS4-HMAC-SHA256 [REDACTED]",
            ),
            ("authorization=abc123 next=1", "authorization=[REDACTED]"),
            (
                "Authorization: Custom-Scheme s3cr3t",
                "Authorization: [REDACTED]",
            ),
            (
                "Authorization: bearer abc",
                "Authorization: bearer [REDACTED]",
            ),
            (
                "curl -H \"Authorization: Bearer abc\" x",
                "curl -H \"Authorization: Bearer [REDACTED]\" x",
            ),
            (
                "{Authorization=Bearer xyz, Accept=json}",
                "{Authorization=Bearer [REDACTED], Accept=json}",
            ),
        ],
    );
    unchanged_all(
        Options::default(),
        &[
            "Authorization: [REDACTED]",
            "Authorization: Bearer [REDACTED]",
        ],
    );
    attributed(
        "Authorization: Bearer fake-token",
        "Authorization: Bearer [REDACTED]",
        "SR-002",
        1,
    );
}

#[test]
fn sr009_cookies() {
    check_all(
        Options::default(),
        &[
            (
                "Cookie: sid=fake; theme=dark",
                "Cookie: sid=[REDACTED]; theme=[REDACTED]",
            ),
            (
                "Set-Cookie: sid=fake; Path=/; HttpOnly",
                "Set-Cookie: sid=[REDACTED]; Path=/; HttpOnly",
            ),
            ("Cookie: a=\"x y\"", "Cookie: a=\"[REDACTED]\""),
            (
                "\"cookie\": \"a=1; b=2\"",
                "\"cookie\": \"a=[REDACTED]; b=[REDACTED]\"",
            ),
            (
                "set-cookie: token=abc; Max-Age=60",
                "set-cookie: token=[REDACTED]; Max-Age=60",
            ),
        ],
    );
    unchanged_all(Options::default(), &["Cookie: sid=[REDACTED]", "Cookie:"]);
    attributed(
        "Cookie: sid=fake; theme=dark",
        "Cookie: sid=[REDACTED]; theme=[REDACTED]",
        "SR-009",
        2,
    );
}

#[test]
fn header_fields_do_not_hide_other_headers() {
    check_all(
        Options::default(),
        &[
            (
                "Cookie: a=b; Authorization: Bearer xyz",
                "Cookie: a=[REDACTED]; Authorization: Bearer [REDACTED]",
            ),
            (
                "Authorization: Basic abc Cookie: s=1",
                "Authorization: Basic [REDACTED] Cookie: s=[REDACTED]",
            ),
        ],
    );
    attributed("Cookie: token=abc", "Cookie: token=[REDACTED]", "SR-009", 1);
}

#[test]
fn scheme_without_credential_is_unchanged() {
    unchanged_all(
        Options::default(),
        &[
            "Authorization: Bearer ",
            "Authorization: Bearer",
            "\"authorization\": \"Basic\"",
        ],
    );
}

#[test]
fn second_run_is_stable_when_contexts_change() {
    // Regression from the idempotence property.
    for input in [
        "/Users/Cookie: a=\"api_key\": \"Authorization: Bearer ",
        "/Users/Cookie: a=b; Authorization: Bearer xyz",
        "Cookie: a='\"api_key\": \";",
        "Cookie: a=DB_PASSWORD=';'",
        "Cookie: a='\u{1b}[31m/Users/Authorization: Bearer ",
        "Cookie: a=Authorization: Bearer \"api_key\": \";\"api_key\": \"password=",
    ] {
        let once = redact(input);
        assert_eq!(redact(&once), once, "input {input:?}");
    }
}

#[test]
fn malformed_cookie_segment_is_conservatively_redacted() {
    check_all(
        Options::default(),
        &[(
            "Cookie: a=Authorization: Bearer \"api_key\": \";\"api_key\": \"password=",
            "Cookie: a=[REDACTED]",
        )],
    );
}

#[test]
fn authorization_credential_ends_at_bracket_and_stays_stable() {
    // TRD §6.3: the credential token ends at `]`; the path after it keeps its own rule.
    let input = "Authorization: Bearer postgres://app:pw@db/x[REDACTED]/home/alex/";
    let once = redact(input);
    assert_eq!(once, "Authorization: Bearer [REDACTED]]/home/[USER]/");
    assert_eq!(redact(&once), once);
}

#[test]
fn secret_value_ends_before_existing_placeholder_and_stays_stable() {
    // TRD §6.2: an unquoted value ends at `[`; the existing placeholder is kept, not counted.
    let input = "--password postgres://app:pw@db/x[REDACTED]/home/alex/";
    let once = redact(input);
    assert_eq!(once, "--password [REDACTED][REDACTED]/home/[USER]/");
    assert_eq!(redact(&once), once);
}

#[test]
fn nested_assignment_in_cookie_value_is_redacted_as_one_value() {
    let input = "Cookie: a=password=\"api_key\": \"; b=plain";
    let once = redact(input);
    assert_eq!(once, "Cookie: a=[REDACTED][REDACTED]");
    assert_eq!(redact(&once), once);
}

#[test]
fn pem_cookie_value_is_left_to_the_pem_detector() {
    for input in [
        "Cookie: a=-----BEGIN PRIVATE KEY-----;-----END PRIVATE KEY-----password=",
        "Cookie: a==-----BEGIN PRIVATE KEY-----;-----END PRIVATE KEY-----password=",
    ] {
        let once = redact(input);
        assert_eq!(redact(&once), once, "input {input:?}");
    }
}

#[test]
fn path_after_cookie_delimiter_is_not_part_of_a_cookie_url_value() {
    let input = "Set-Cookie: s=postgres://app:pw@db/x;/home/alex/";
    let once = redact(input);
    assert_eq!(once, "Set-Cookie: s=[REDACTED];/home/[USER]/");
    assert_eq!(redact(&once), once);
}

#[test]
fn secret_value_ends_at_bracket_before_windows_home() {
    let input = "--password postgres://app:pw@db/x[C:\\Users\\alex\\";
    let once = redact(input);
    assert_eq!(once, "--password [REDACTED][C:\\Users\\[USER]\\");
    assert_eq!(redact(&once), once);
}

#[test]
fn secret_value_ends_at_bracket_before_posix_home() {
    let input = "password=postgres://app:pw@db/x[/home/alex/";
    let once = redact(input);
    assert_eq!(once, "password=[REDACTED][/home/[USER]/");
    assert_eq!(redact(&once), once);
}

#[test]
fn secret_value_ends_at_bracket_before_url() {
    let input = "password=postgres://app:pw@db/x[https:///home/alex/";
    let once = redact(input);
    assert_eq!(once, "password=[REDACTED][https:///home/[USER]/");
    assert_eq!(redact(&once), once);
}

/// Values end at their delimiter (TRD §6.2); later text on the line keeps its own rules.
#[test]
fn sr001_value_does_not_absorb_following_text() {
    check_all(
        Options::default(),
        &[
            (
                "password=x and the full log is at /home/alex/app.log",
                "password=[REDACTED] and the full log is at /home/[USER]/app.log",
            ),
            (
                "password=hunter2 user=bob (see /home/alex/notes.txt)",
                "password=[REDACTED] user=bob (see /home/[USER]/notes.txt)",
            ),
            (
                "password=abc [see https://example.com/doc]",
                "password=[REDACTED] [see https://example.com/doc]",
            ),
        ],
    );
}

/// A quoted value ends at its own closing quote, even when a later field holds a private key.
#[test]
fn sr001_quoted_value_does_not_cross_fields() {
    check_all(
        Options::default(),
        &[(
            r#"{"token": "x", "note": "keep me", "pem": "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n", "user": "bob"}"#,
            r#"{"token": "[REDACTED]", "note": "keep me", "pem": "-----BEGIN PRIVATE KEY-----[PRIVATE KEY REDACTED]-----END PRIVATE KEY-----\n", "user": "bob"}"#,
        )],
    );
}

/// A header that follows another header's field on the same line is still parsed.
#[test]
fn headers_after_a_cookie_field_are_redacted() {
    check_all(
        Options::default(),
        &[
            (
                "Cookie: a=b; Cookie: c=fake-two",
                "Cookie: a=[REDACTED]; Cookie: c=[REDACTED]",
            ),
            (
                "Cookie: a=b; Authorization: Bearer fake-two",
                "Cookie: a=[REDACTED]; Authorization: Bearer [REDACTED]",
            ),
            (
                "Cookie: a=b;Cookie: c=fake-two",
                "Cookie: a=[REDACTED];Cookie: c=[REDACTED]",
            ),
        ],
    );
}

/// Cookie names are kept even when they are not RFC 6265 tokens; only values are redacted.
#[test]
fn sr009_keeps_names_and_set_cookie_attributes() {
    check_all(
        Options::default(),
        &[
            (
                "Cookie: a=b; my session=xyz",
                "Cookie: a=[REDACTED]; my session=[REDACTED]",
            ),
            (
                "Set-Cookie: s=token=abc; Path=/; HttpOnly",
                "Set-Cookie: s=[REDACTED]; Path=/; HttpOnly",
            ),
        ],
    );
}
