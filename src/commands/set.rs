use anyhow::{Result, bail};
use aws_sdk_ssm::Client;
use std::collections::HashSet;

use crate::app::resolve_app;
use crate::cli::SetArgs;
use crate::commands::put::put_kvs;
use crate::env_map::parse_tags;
use crate::ssm::build_plain_secure_sets;
use crate::util::read_secret_tty;

/// Interactive secret entry: prompts (no-echo) once per KEY, then routes
/// the collected pairs through the same `put_kvs` path as `put`.
///
/// Why a separate subcommand instead of overloading `put`:
/// - `put` stays a pure, scriptable KEY=VALUE / --env pipeline
/// - `set` is unambiguously the "I'm typing a secret right now" entry point
/// - No mixed-mode (KEY=v + bare KEY in one call) ambiguity
pub async fn cmd_set(client: &Client, args: SetArgs) -> Result<()> {
    let SetArgs {
        keys,
        app,
        plain_all,
        plain_keys,
        secure_keys,
        tags: raw_tags,
    } = args;

    let app = resolve_app(app)?;

    validate_set_keys(&keys)?;

    let mut kvs: Vec<(String, String)> = Vec::with_capacity(keys.len());
    for k in &keys {
        let value = read_secret_tty(&format!("Value for {}: ", k))?;
        if value.is_empty() {
            bail!("aborted: empty value for {}", k);
        }
        kvs.push((k.clone(), value));
    }

    let (plain_set, secure_set) = build_plain_secure_sets(plain_keys, secure_keys)?;

    let extra_tags = parse_tags(&raw_tags)?;
    if extra_tags.iter().any(|(k, _)| k == "app") {
        bail!("`app` tag is reserved; do not pass --tag app=...");
    }

    put_kvs(
        client,
        &kvs,
        &app,
        plain_all,
        &plain_set,
        &secure_set,
        &extra_tags,
    )
    .await
}

/// Reject any positional that isn't a clean bare KEY. `=` is the `put`
/// shape — accepting it here would silently put the value the user typed
/// after `=` while *also* still working, defeating the no-history promise
/// of `set` for users who typo'd.
fn validate_set_keys(keys: &[String]) -> Result<()> {
    let mut seen: HashSet<&str> = HashSet::new();
    for k in keys {
        if k.contains('=') {
            bail!(
                "`set` takes bare KEY only (got {:?}). Use `ssmm put KEY=VALUE` for non-interactive writes.",
                k
            );
        }
        let trimmed = k.trim();
        if trimmed.is_empty() {
            bail!("empty KEY in arguments");
        }
        if trimmed.contains(char::is_whitespace) {
            bail!("invalid KEY (contains whitespace): {:?}", trimmed);
        }
        if !seen.insert(k.as_str()) {
            bail!("duplicate KEY in arguments: {}", k);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_set_keys;

    #[test]
    fn accepts_plain_keys() {
        validate_set_keys(&[
            "SLACK_BOT_TOKEN".to_string(),
            "API_KEY".to_string(),
        ])
        .unwrap();
    }

    #[test]
    fn rejects_equals_in_arg() {
        let err = validate_set_keys(&["FOO=bar".to_string()]).unwrap_err();
        assert!(err.to_string().contains("bare KEY only"), "got: {}", err);
    }

    #[test]
    fn rejects_whitespace_in_key() {
        let err = validate_set_keys(&["BAD KEY".to_string()]).unwrap_err();
        assert!(err.to_string().contains("whitespace"), "got: {}", err);
    }

    #[test]
    fn rejects_empty_key() {
        let err = validate_set_keys(&["".to_string()]).unwrap_err();
        assert!(err.to_string().contains("empty"), "got: {}", err);
    }

    #[test]
    fn rejects_duplicate_keys() {
        let err = validate_set_keys(&[
            "FOO".to_string(),
            "FOO".to_string(),
        ])
        .unwrap_err();
        assert!(err.to_string().contains("duplicate"), "got: {}", err);
    }
}
