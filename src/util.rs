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

pub fn print_entry(key: &str, value: Option<&str>, secure: bool, keys_only: bool, indent: &str) {
    let label = if secure { "🔒" } else { "  " };
    if keys_only {
        println!("{}{} {}", indent, label, key);
    } else {
        println!("{}{} {}={}", indent, label, key, value.unwrap_or(""));
    }
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
}
