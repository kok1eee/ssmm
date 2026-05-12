use anyhow::Result;
use futures::stream::{self, StreamExt, TryStreamExt};
use sha2::{Digest, Sha256};
use std::io::{self, Write};

pub async fn run_bounded<F, Fut, T>(futs: F, limit: usize) -> Result<Vec<T>>
where
    F: IntoIterator<Item = Fut>,
    Fut: std::future::Future<Output = Result<T>>,
{
    stream::iter(futs)
        .buffer_unordered(limit)
        .try_collect()
        .await
}

pub fn hash8(value: &str) -> String {
    let mut h = Sha256::new();
    h.update(value.as_bytes());
    format!("{:x}", h.finalize())[..8].to_string()
}

pub fn confirm_prompt(msg: &str) -> Result<bool> {
    print!("{} [y/N]: ", msg);
    io::stdout().flush()?;
    let mut buf = String::new();
    io::stdin().read_line(&mut buf)?;
    Ok(matches!(buf.trim(), "y" | "Y" | "yes" | "YES"))
}

/// How `list` should render parameter values.
///
/// Default behaviour masks SecureString values as `***`. Plain String values
/// are always shown — SSM SecureString is the only signal we have that a value
/// should be treated as secret. `--reveal` opts in to plaintext for SecureString
/// too; `--keys-only` hides values entirely.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisplayMode {
    /// Show only keys, no values (`--keys-only`).
    KeysOnly,
    /// SecureString masked as `***`, String shown. Default.
    Default,
    /// Show plaintext for all values including SecureString (`--reveal`).
    Reveal,
}

pub fn format_entry(
    key: &str,
    value: Option<&str>,
    secure: bool,
    mode: DisplayMode,
    indent: &str,
) -> String {
    let label = if secure { "🔒" } else { "  " };
    match mode {
        DisplayMode::KeysOnly => format!("{}{} {}", indent, label, key),
        DisplayMode::Default if secure => format!("{}{} {}=***", indent, label, key),
        DisplayMode::Default | DisplayMode::Reveal => {
            format!("{}{} {}={}", indent, label, key, value.unwrap_or(""))
        }
    }
}

pub fn print_entry(
    key: &str,
    value: Option<&str>,
    secure: bool,
    mode: DisplayMode,
    indent: &str,
) {
    println!("{}", format_entry(key, value, secure, mode, indent));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash8_is_deterministic_and_length_8() {
        assert_eq!(hash8("hello"), hash8("hello"));
        assert_ne!(hash8("hello"), hash8("world"));
        assert_eq!(hash8("hello").len(), 8);
    }

    #[test]
    fn format_entry_default_masks_securestring() {
        let out = format_entry("API_KEY", Some("sk-secret-xyz"), true, DisplayMode::Default, "");
        assert!(!out.contains("sk-secret"), "secret value leaked: {out}");
        assert!(out.contains("API_KEY=***"), "expected masked output, got {out}");
    }

    #[test]
    fn format_entry_default_shows_plain_string() {
        let out = format_entry(
            "LOG_DIR",
            Some("/var/log/app"),
            false,
            DisplayMode::Default,
            "",
        );
        assert!(
            out.contains("LOG_DIR=/var/log/app"),
            "expected plain value, got {out}"
        );
    }

    #[test]
    fn format_entry_keys_only_hides_value_for_both_types() {
        let secure_out =
            format_entry("API_KEY", Some("sk-secret"), true, DisplayMode::KeysOnly, "");
        let plain_out =
            format_entry("LOG_DIR", Some("/var/log"), false, DisplayMode::KeysOnly, "");
        assert!(!secure_out.contains("="), "keys-only leaked value: {secure_out}");
        assert!(!plain_out.contains("="), "keys-only leaked value: {plain_out}");
        assert!(secure_out.contains("API_KEY"));
        assert!(plain_out.contains("LOG_DIR"));
    }

    #[test]
    fn format_entry_reveal_shows_securestring() {
        let out = format_entry(
            "API_KEY",
            Some("sk-secret-xyz"),
            true,
            DisplayMode::Reveal,
            "",
        );
        assert!(
            out.contains("API_KEY=sk-secret-xyz"),
            "expected revealed value, got {out}"
        );
    }
}
