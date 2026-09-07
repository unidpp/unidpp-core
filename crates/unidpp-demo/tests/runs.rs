//! Workspace test: the demo binaries run successfully and deterministically.
//!
//! Pattern choice (documented per the task): `unidpp-demo` is both a
//! library and a binary, so these integration tests exercise the *real
//! compiled CLI* through `env!("CARGO_BIN_EXE_unidpp-demo")` — asserting
//! exit status 0 and the presence of the load-bearing sections in stdout
//! — and additionally assert byte-level determinism by running each
//! scenario twice with the same seed and comparing stdout. The scenario
//! functions themselves also embed `assert!`s for their semantic
//! guarantees (taint propagation, budget margins, verdict outcomes), so a
//! successful run is itself a passing conformance check.

use std::process::{Command, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_unidpp-demo");

fn run_cli(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(BIN)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .expect("the unidpp-demo binary starts");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn every_scenario_exits_zero_with_its_landmarks() {
    let cases: &[(&str, &[&str])] = &[
        (
            "battery-loop",
            &[
                "UniDPP demonstration run",
                "Combine (N -> 1)",
                "Split (1 -> N)",
                "Blind installation",
                "taint propagation",
                "End-of-waste",
                "Tier-A packing",
                "verdict 1",
                "verdict 4",
                "DEGRADED (signatures-framed-only)",
                "DEGRADED (stale-data",
                "DEGRADED (offline-no-anchor)",
                "FAIL (broken-chain)",
                "VOIDS AB INITIO",
                "margin +",
                "Exit status 0",
            ],
        ),
        (
            "car",
            &[
                "federation of passports",
                "Issuance of the battery passport",
                "Blind installation",
                "Custody transfer",
                "Milestone record",
                "Predicate-based recall",
                "battery.firmware < \"2.3.1\"",
                "As-of readings",
                "recall-active",
                "Tier-A packing",
                "Exit status 0",
            ],
        ),
        (
            "laptop",
            &[
                "Issuance of the laptop passport",
                "dated binding",
                "Blind installation",
                "Custody transfer",
                "Software update",
                "Part replacement",
                "dormant identifier",
                "Two lenses, two verdicts",
                "coverage-incomplete",
                "Tier-A packing",
                "Exit status 0",
            ],
        ),
    ];
    for (name, landmarks) in cases {
        let (code, stdout, stderr) = run_cli(&["--scenario", name]);
        assert_eq!(code, 0, "{name}: exit {code}, stderr: {stderr}");
        for landmark in *landmarks {
            assert!(
                stdout.contains(landmark),
                "{name}: stdout lacks landmark `{landmark}`"
            );
        }
    }
}

#[test]
fn output_is_deterministic_across_runs() {
    for name in unidpp_demo::SCENARIOS {
        let (c1, o1, _) = run_cli(&["--scenario", name]);
        let (c2, o2, _) = run_cli(&["--scenario", name]);
        assert_eq!(c1, 0);
        assert_eq!(c2, 0);
        assert_eq!(o1, o2, "{name}: two seeded runs differ");
    }
}

#[test]
fn different_seeds_change_the_blind_commitments() {
    // The narrative skeleton stays, but salted commitments must move with
    // the seed (salt whitening is observable, not decorative).
    let (_, a, _) = run_cli(&["--scenario", "battery-loop", "--seed", "0x01"]);
    let (_, b, _) = run_cli(&["--scenario", "battery-loop", "--seed", "0x02"]);
    assert_ne!(a, b, "seed change had no effect on the trace");
    // And the car identity never leaks under any seed.
    assert!(!a.contains("car-eu-42:"));
}

#[test]
fn usage_errors_exit_two() {
    let (code, _, stderr) = run_cli(&["--scenario", "nope"]);
    assert_eq!(code, 2);
    assert!(stderr.contains("unknown scenario"));
    let (code, _, _) = run_cli(&["--frobnicate"]);
    assert_eq!(code, 2);
    let (code, stdout, _) = run_cli(&["--list"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("battery-loop"));
    let (code, _, _) = run_cli(&["--help"]);
    assert_eq!(code, 0);
}

#[test]
fn library_scenarios_run_in_process() {
    // Direct invocation of the scenario functions (no subprocess), as the
    // alternative pattern noted in the task.
    for name in unidpp_demo::SCENARIOS {
        let mut buf: Vec<u8> = Vec::new();
        unidpp_demo::run(name, &mut buf, 0x756e_6964_7070)
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        assert!(buf.len() > 1000, "{name}: trace suspiciously short");
        assert!(String::from_utf8_lossy(&buf).contains("Exit status 0"));
    }
}
