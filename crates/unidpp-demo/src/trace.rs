//! The narration device: a deterministic, line-oriented trace printer.
//!
//! Layout (76-column target, ASCII only so the output embeds cleanly in
//! documentation):
//!
//! ```text
//! -- Step 3: Combine (N -> 1) -------------------------------------
//! event:      Combine by custodian (transformer) / pack-maker at ...
//! commitment: 9c17d2ab04fe33c1.. (salted; H(salt || prev || body))
//! state:      pack-1: 1 -> 2 sealed events; mass balance 25 kg in, ...
//! note:       The output issuance carries inputReferences with as-of
//!              state hashes; quantities are new measured facts ... (I4)
//! ```

use std::io::Write;

use crate::DemoError;

const LINE: usize = 76;
const GUTTER: usize = 2; // leading spaces of every trace line
const KEY_WIDTH: usize = 11; // "commitment" fits; shorter keys are padded

/// Wraps `text` at [`LINE`] columns, indenting continuation lines by
/// `indent` spaces. Deterministic; ASCII input assumed.
fn wrap(text: &str, indent: usize) -> String {
    let width = LINE.saturating_sub(indent).max(16);
    let mut lines: Vec<String> = Vec::new();
    let mut current = String::new();
    for word in text.split_whitespace() {
        let candidate = if current.is_empty() {
            word.len()
        } else {
            current.len() + 1 + word.len()
        };
        if !current.is_empty() && candidate > width {
            lines.push(std::mem::take(&mut current));
        }
        if !current.is_empty() {
            current.push(' ');
        }
        current.push_str(word);
    }
    if !current.is_empty() {
        lines.push(current);
    }
    let pad = " ".repeat(indent);
    lines
        .iter()
        .map(|l| format!("{pad}{l}"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Renders `key: value` with wrapped continuation lines aligned under the
/// value column.
fn kv_line(key: &str, value: &str) -> String {
    let value_indent = GUTTER + KEY_WIDTH + 2;
    let label = format!("{:<width$}", format!("{key}:"), width = KEY_WIDTH);
    let body = wrap(value, value_indent);
    let mut out = String::new();
    for (i, line) in body.lines().enumerate() {
        if i == 0 {
            out.push_str(&format!("{}{} {}", " ".repeat(GUTTER), label, line.trim_start()));
        } else {
            out.push('\n');
            out.push_str(line);
        }
    }
    out
}

/// A step-numbered trace writer.
pub struct Trace<'w> {
    out: &'w mut dyn Write,
    step: usize,
}

impl<'w> Trace<'w> {
    pub fn new(out: &'w mut dyn Write) -> Trace<'w> {
        Trace { out, step: 0 }
    }

    fn put(&mut self, s: &str) -> Result<(), DemoError> {
        writeln!(self.out, "{s}").map_err(DemoError::from)
    }

    /// The run banner (scenario, seed, library note).
    pub fn header(&mut self, scenario: &str, seed: u64) -> Result<(), DemoError> {
        self.put("===========================================================================")?;
        self.put("UniDPP demonstration run")?;
        self.put(&wrap(
            &format!(
                "scenario : {scenario}   seed : 0x{seed:016x}   lib : unidpp-core {}",
                env!("CARGO_PKG_VERSION")
            ),
            0,
        ))?;
        self.put(&wrap(
            "seed drives deterministic salt derivation only; production salts must \
             come from a CSPRNG. Every timestamp below is fixed, so identical seeds \
             yield byte-identical traces.",
            0,
        ))?;
        self.put("===========================================================================")?;
        self.blank()
    }

    /// Scene-setting paragraph before the first step.
    pub fn scene(&mut self, text: &str) -> Result<(), DemoError> {
        self.put(&wrap(&format!("SCENE  {text}"), 0))?;
        self.blank()
    }

    /// Advance to the next step and print its title rule.
    pub fn step(&mut self, title: &str) -> Result<(), DemoError> {
        self.step += 1;
        let head = format!("-- Step {}: {} ", self.step, title);
        let fill = LINE.saturating_sub(head.len());
        self.put(&format!("{head}{}", "-".repeat(fill)))?;
        Ok(())
    }

    /// A labelled single value; long values wrap under the value column.
    pub fn kv(&mut self, key: &str, value: &str) -> Result<(), DemoError> {
        self.put(&kv_line(key, value))
    }

    /// A wrapped rationale line citing the invariants.
    pub fn note(&mut self, text: &str) -> Result<(), DemoError> {
        self.put(&kv_line("note", text))
    }

    /// A raw (pre-formatted) line, still inside the 2-space gutter.
    pub fn raw(&mut self, line: &str) -> Result<(), DemoError> {
        self.put(&format!("  {line}"))
    }

    pub fn blank(&mut self) -> Result<(), DemoError> {
        self.put("")
    }

    /// Closing rule.
    pub fn done(&mut self) -> Result<(), DemoError> {
        self.put("===========================================================================")?;
        self.put("End of scenario. Exit status 0.")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_is_deterministic_and_indented() {
        let text = "The output passport's issuance event carries inputReferences \
                    with as-of state hashes, so the new passport hash-links its sources.";
        let w = wrap(text, 13);
        assert_eq!(w, wrap(text, 13));
        for line in w.lines() {
            assert!(line.len() <= LINE, "line too long: {line}");
        }
        assert!(w.contains("\n             "), "continuation indent missing");
    }

    #[test]
    fn kv_aligns_continuation_under_value() {
        let line = kv_line(
            "commitment",
            "9c17d2ab04fe33c1.. unsalted; H(prev || canonical body) covers the full \
             sealed prefix of the pack-1 log",
        );
        let mut rows = line.split('\n');
        assert!(rows.next().unwrap().starts_with("  commitment: "));
        let second = rows.next().unwrap();
        assert_eq!(&second[..15], "               ");
    }

    #[test]
    fn trace_steps_increment() {
        let mut buf: Vec<u8> = Vec::new();
        {
            let mut tr = Trace::new(&mut buf);
            tr.header("test", 1).unwrap();
            tr.scene("a scene").unwrap();
            tr.step("first").unwrap();
            tr.kv("event", "Issuance").unwrap();
            tr.note("a note (I4).").unwrap();
            tr.step("second").unwrap();
            tr.done().unwrap();
        }
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("-- Step 1: first"));
        assert!(s.contains("-- Step 2: second"));
        assert!(s.contains("event:      Issuance"));
        assert!(s.contains("note:       a note (I4)."));
    }
}
