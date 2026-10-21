//! SR-006 private IP addresses (off by default).
mod common;
use common::*;
use spymonk_redact_core::Options;

#[test]
fn sr006_off_by_default() {
    unchanged_all(
        Options::default(),
        &["host=10.0.0.8:5432", "addr=[fd12:3456::1]:443"],
    );
}

#[test]
fn sr006_ipv4_private_ranges() {
    check_all(
        PRIVATE_IP_ON,
        &[
            ("host=10.0.0.8:5432", "host=[PRIVATE IP REDACTED]:5432"),
            ("192.168.1.1", "[PRIVATE IP REDACTED]"),
            (
                "172.16.0.1 and 172.31.255.255",
                "[PRIVATE IP REDACTED] and [PRIVATE IP REDACTED]",
            ),
            ("net 10.0.0.0/8", "net [PRIVATE IP REDACTED]/8"),
            ("host 10.0.0.1.", "host [PRIVATE IP REDACTED]."),
            ("(10.1.2.3)", "([PRIVATE IP REDACTED])"),
        ],
    );
    unchanged_all(
        PRIVATE_IP_ON,
        &[
            "host=172.32.0.1",
            "110.0.0.1",
            "10.0.0.256",
            "1.10.0.0.1",
            "10.0.0.1.5",
            "10.00.0.1",
            "v10.0.0.1",
            "8.8.8.8",
            "127.0.0.1",
            "169.254.1.1",
            "100.64.0.1",
        ],
    );
}

#[test]
fn sr006_ipv6_unique_local() {
    check_all(
        PRIVATE_IP_ON,
        &[
            (
                "addr=[fd12:3456::1]:443",
                "addr=[[PRIVATE IP REDACTED]]:443",
            ),
            ("fd12:3456::1", "[PRIVATE IP REDACTED]"),
            ("fc00::", "[PRIVATE IP REDACTED]"),
            ("FD00:0:0:0:0:0:0:1 up", "[PRIVATE IP REDACTED] up"),
            ("fd00::1%eth0", "[PRIVATE IP REDACTED]%eth0"),
            ("fd00::10.0.0.1", "[PRIVATE IP REDACTED]"),
        ],
    );
    unchanged_all(
        PRIVATE_IP_ON,
        &[
            "fe80::1",
            "2001:db8::1",
            "fdisk -l",
            "sha fd3a9b4c",
            "fd12:34:56",
            "fd00:::1",
            "fd00::1::2",
            "ffd0::1",
        ],
    );
    attributed_with_ip();
}

fn attributed_with_ip() {
    let (out, s) = run("ip=192.168.0.10", PRIVATE_IP_ON);
    assert_eq!(out, "ip=[PRIVATE IP REDACTED]");
    assert_eq!(count(&s, "SR-006"), 1);
}
