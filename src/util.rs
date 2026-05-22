use anyhow::{Context, Result, bail};
use futures::stream::{self, StreamExt, TryStreamExt};
use sha2::{Digest, Sha256};
use std::io::{self, BufRead, Write};
use std::os::unix::io::AsRawFd;

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

/// Read a single line from stdin with terminal echo disabled, so the typed
/// value never lands in shell history, terminal scrollback (visibly), or
/// `ps`/`/proc/<pid>/cmdline`. Errors when stdin is not a TTY — we refuse
/// to silently degrade because the caller asked for an interactive secret.
///
/// The prompt is written to stderr so it doesn't pollute stdout pipelines.
/// Trailing CR/LF is stripped from the returned value. The value itself is
/// never echoed, logged, or returned through Display anywhere.
pub fn read_secret_tty(prompt: &str) -> Result<String> {
    let stdin = io::stdin();
    let fd = stdin.as_raw_fd();
    // Safety: libc FFI on a valid fd; termios struct is zero-initialized
    // before tcgetattr writes into it. tcsetattr is called with the
    // original termios in the restore path to guarantee echo comes back
    // on even if read_line fails.
    unsafe {
        if libc::isatty(fd) == 0 {
            bail!("stdin is not a TTY; pass KEY=VALUE or --env <file> for non-interactive use");
        }
        let mut term: libc::termios = std::mem::zeroed();
        if libc::tcgetattr(fd, &mut term) != 0 {
            bail!("tcgetattr failed: {}", io::Error::last_os_error());
        }
        let original = term;
        term.c_lflag &= !libc::ECHO;
        if libc::tcsetattr(fd, libc::TCSAFLUSH, &term) != 0 {
            bail!("tcsetattr failed: {}", io::Error::last_os_error());
        }

        eprint!("{}", prompt);
        io::stderr().flush().ok();

        let mut buf = String::new();
        let read_result = stdin.lock().read_line(&mut buf);

        // Restore termios before doing anything else; ignore errors here
        // since we'd otherwise hide the real read error and there's no
        // useful recovery.
        libc::tcsetattr(fd, libc::TCSAFLUSH, &original);
        // Echo was off so the user's Enter did not produce a newline on
        // screen; emit one for layout sanity.
        eprintln!();

        read_result.context("read_line from stdin")?;
        if buf.ends_with('\n') {
            buf.pop();
        }
        if buf.ends_with('\r') {
            buf.pop();
        }
        Ok(buf)
    }
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
