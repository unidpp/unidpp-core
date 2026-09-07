//! `unidpp-demo`: the narrated demonstration CLI.
//!
//! ```text
//! cargo run -p unidpp-demo -- --scenario battery-loop
//! cargo run -p unidpp-demo -- --scenario car
//! cargo run -p unidpp-demo -- --scenario laptop
//! ```
//!
//! Exit codes: 0 on a completed run, 1 on an internal failure, 2 on a
//! usage error. Output is deterministic for a given seed (see the library
//! documentation).

use std::io::Write;
use std::process::ExitCode;

const USAGE: &str = "\
unidpp-demo - narrated UniDPP demonstration scenarios

USAGE:
    unidpp-demo [OPTIONS]

OPTIONS:
    --scenario <NAME>  scenario to run (default: battery-loop)
    --seed <HEX>       64-bit seed (hex, 0x-prefixed or bare) driving
                       deterministic salt derivation (default: 0x756e69647070)
    --list             list the available scenarios and exit
    -h, --help         print this help and exit

SCENARIOS:
    battery-loop  cells -> pack (combine) -> split harvest -> blind install
                  -> theft taint -> end-of-waste -> Tier A -> graded verdicts
    car           parent car + battery child passports, blind install edge,
                  predicate-based recall, as-of verification readings
    laptop        one neutral core, EU + JP profiles, custody, firmware
                  update, part replace, per-lens coverage verdicts";

fn default_seed() -> u64 {
    0x756e_6964_7070
}

fn parse_seed(s: &str) -> Result<u64, String> {
    let body = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    u64::from_str_radix(body, 16).map_err(|_| format!("seed `{s}` is not a hexadecimal u64"))
}

fn fail_usage(msg: &str) -> ExitCode {
    eprintln!("unidpp-demo: {msg}");
    eprintln!("try `unidpp-demo --help`");
    ExitCode::from(2)
}

fn run() -> Result<ExitCode, String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut scenario = "battery-loop".to_string();
    let mut seed = default_seed();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--scenario" | "-s" => {
                i += 1;
                scenario = args
                    .get(i)
                    .ok_or_else(|| "--scenario requires a value".to_string())?
                    .clone();
            }
            "--seed" => {
                i += 1;
                let v = args
                    .get(i)
                    .ok_or_else(|| "--seed requires a value".to_string())?;
                seed = parse_seed(v)?;
            }
            "--list" => {
                for (name, blurb) in unidpp_demo::SCENARIO_BLURBS {
                    println!("{name:<14} {blurb}");
                }
                return Ok(ExitCode::SUCCESS);
            }
            "--help" | "-h" => {
                println!("{USAGE}");
                return Ok(ExitCode::SUCCESS);
            }
            other => return Err(format!("unknown argument `{other}`")),
        }
        i += 1;
    }
    if !unidpp_demo::SCENARIOS.contains(&scenario.as_str()) {
        return Err(format!(
            "unknown scenario `{scenario}` (available: {})",
            unidpp_demo::SCENARIOS.join(", ")
        ));
    }
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    match unidpp_demo::run(&scenario, &mut out, seed) {
        Ok(()) => {}
        // A consumer that closed the pipe (`... | head`) is not a failure.
        Err(e) if e.is_broken_pipe() => return Ok(ExitCode::SUCCESS),
        Err(e) => return Err(e.to_string()),
    }
    out.flush().map_err(|e| e.to_string())?;
    Ok(ExitCode::SUCCESS)
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(msg) => fail_usage(&msg),
    }
}
