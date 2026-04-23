use anyhow::{Result, bail};
use std::sync::OnceLock;

pub const SSMM_ENV_VAR: &str = "SSMM_PREFIX_ROOT";

/// SSM PutParameter の TPS (~3) に合わせたデフォルト書き込み並列度。
/// `--write-concurrency N` で上書き可。read 系はより高くても安全。
const DEFAULT_WRITE_CONCURRENCY: usize = 3;
const DEFAULT_READ_CONCURRENCY: usize = 10;

static PREFIX_ROOT: OnceLock<String> = OnceLock::new();
static SHARED_PREFIX: OnceLock<String> = OnceLock::new();
static WRITE_CONCURRENCY: OnceLock<usize> = OnceLock::new();
static READ_CONCURRENCY: OnceLock<usize> = OnceLock::new();
static ADVANCED_TIER: OnceLock<bool> = OnceLock::new();
static KMS_KEY_ID: OnceLock<Option<String>> = OnceLock::new();

pub fn prefix_root() -> &'static str {
    PREFIX_ROOT
        .get()
        .map(String::as_str)
        .expect("prefix_root called before PREFIX_ROOT is initialized (main forgot to set?)")
}

pub fn shared_prefix() -> &'static str {
    SHARED_PREFIX
        .get()
        .map(String::as_str)
        .expect("shared_prefix called before SHARED_PREFIX is initialized (main forgot to set?)")
}

pub fn write_concurrency() -> usize {
    WRITE_CONCURRENCY
        .get()
        .copied()
        .unwrap_or(DEFAULT_WRITE_CONCURRENCY)
}

pub fn read_concurrency() -> usize {
    READ_CONCURRENCY
        .get()
        .copied()
        .unwrap_or(DEFAULT_READ_CONCURRENCY)
}

pub fn advanced_tier() -> bool {
    ADVANCED_TIER.get().copied().unwrap_or(false)
}

pub fn kms_key_id() -> Option<&'static str> {
    KMS_KEY_ID.get().and_then(|o| o.as_deref())
}

pub fn init(
    prefix: String,
    write_concurrency: Option<usize>,
    read_concurrency: Option<usize>,
    advanced: bool,
    kms_key_id: Option<String>,
) -> Result<()> {
    let root = prefix.trim_end_matches('/').to_string();
    if !root.starts_with('/') {
        bail!("prefix must start with '/': got {:?}", root);
    }
    let shared = format!("{}/shared", root);
    PREFIX_ROOT
        .set(root)
        .expect("PREFIX_ROOT should only be set once during startup");
    SHARED_PREFIX
        .set(shared)
        .expect("SHARED_PREFIX should only be set once during startup");
    if let Some(n) = write_concurrency {
        if n == 0 {
            bail!("--write-concurrency must be >= 1");
        }
        WRITE_CONCURRENCY.set(n).ok();
    }
    if let Some(n) = read_concurrency {
        if n == 0 {
            bail!("--read-concurrency must be >= 1");
        }
        READ_CONCURRENCY.set(n).ok();
    }
    ADVANCED_TIER.set(advanced).ok();
    KMS_KEY_ID.set(kms_key_id).ok();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[should_panic(expected = "prefix_root called before PREFIX_ROOT is initialized")]
    fn prefix_root_panics_without_explicit_config() {
        // v0.3.0: 明示的な --prefix / $SSMM_PREFIX_ROOT 無しでは panic。
        // main で必ず .set() してから呼ばれる前提。OSS で他チームが空リストに
        // 戸惑わないよう、デフォルトを撤廃して明示構成を強制する
        let _ = prefix_root();
    }
}
