use anyhow::{Context, Result, anyhow};
use aws_sdk_ssm::Client;
use aws_sdk_ssm::types::{Parameter, ParameterStringFilter, ParameterType, Tag};
use std::collections::HashSet;

use crate::config::{read_concurrency, write_concurrency};
use crate::util::run_bounded;

pub fn ssm_name_to_env_key(name: &str, prefix: &str) -> String {
    let trimmed_prefix = format!("{}/", prefix.trim_end_matches('/'));
    let rest = name.strip_prefix(&trimmed_prefix).unwrap_or(name);
    rest.replace(['/', '-'], "_").to_uppercase()
}

/// <root>/<app>/<tail...> → <TAIL_UPCASE_UNDERSCORED>   (app セグメントを落とす)
pub fn ssm_name_to_env_key_from_root(name: &str, root: &str) -> String {
    let rest = name.strip_prefix(&format!("{}/", root)).unwrap_or(name);
    let after_app = rest.split_once('/').map(|(_, tail)| tail).unwrap_or("");
    after_app.replace(['/', '-'], "_").to_uppercase()
}

pub fn env_key_to_ssm_tail(key: &str) -> String {
    key.to_lowercase().replace('_', "-")
}

pub fn build_param_name(prefix: &str, env_key: &str) -> String {
    format!("{}/{}", prefix, env_key_to_ssm_tail(env_key))
}

/// Heuristic: default to SecureString (conservative). Flip to String only for
/// suffixes that strongly imply structural/public config (paths, hostnames,
/// ports, region strings, Slack channel IDs, etc.).
///
/// `_url` is intentionally NOT in the safe list — URLs commonly embed
/// credentials (e.g. `postgres://user:pass@host/db`, Slack webhook URLs,
/// Sentry DSNs). Leaking them as plaintext SSM parameters is the #1
/// real-world foot-gun. Users who want plaintext storage can pass
/// `--plain KEY` explicitly.
pub fn should_be_secure(key: &str) -> bool {
    let lc = key.to_lowercase();
    const NON_SECRET_SUFFIXES: &[&str] = &[
        "_path",
        "_dir",
        "_channel",
        "_name",
        "_host",
        "_port",
        "_region",
        "_endpoint",
    ];
    !NON_SECRET_SUFFIXES.iter().any(|s| lc.ends_with(s))
}

pub fn build_tag(k: &str, v: &str) -> Result<Tag> {
    Tag::builder()
        .key(k)
        .value(v)
        .build()
        .map_err(|e| anyhow!("build tag {}={}: {}", k, v, e))
}

pub fn build_tags(pairs: &[(String, String)]) -> Result<Vec<Tag>> {
    pairs.iter().map(|(k, v)| build_tag(k, v)).collect()
}

/// put 時の型判定の根拠を出力用に記録する
#[derive(Clone, Copy)]
pub enum TypeReason {
    ForcedPlainAll,
    ForcedPlainKey,
    ForcedSecureKey,
    AutoSuffix,
    AutoDefault,
}

impl TypeReason {
    pub fn label(self) -> &'static str {
        match self {
            TypeReason::ForcedPlainAll => "forced: --plain-all",
            TypeReason::ForcedPlainKey => "forced: --plain-key",
            TypeReason::ForcedSecureKey => "forced: --secure",
            TypeReason::AutoSuffix => "auto: suffix",
            TypeReason::AutoDefault => "auto: default",
        }
    }
}

pub fn resolve_type(
    key: &str,
    plain_all: bool,
    plain_keys: &HashSet<String>,
    secure_keys: &HashSet<String>,
) -> (ParameterType, TypeReason) {
    if plain_all {
        return (ParameterType::String, TypeReason::ForcedPlainAll);
    }
    if secure_keys.contains(key) {
        return (ParameterType::SecureString, TypeReason::ForcedSecureKey);
    }
    if plain_keys.contains(key) {
        return (ParameterType::String, TypeReason::ForcedPlainKey);
    }
    if should_be_secure(key) {
        (ParameterType::SecureString, TypeReason::AutoDefault)
    } else {
        (ParameterType::String, TypeReason::AutoSuffix)
    }
}

pub async fn get_parameters_by_path(client: &Client, prefix: &str) -> Result<Vec<Parameter>> {
    let mut all = Vec::new();
    let mut next: Option<String> = None;
    loop {
        let mut req = client
            .get_parameters_by_path()
            .path(prefix)
            .recursive(true)
            .with_decryption(true);
        if let Some(t) = &next {
            req = req.next_token(t);
        }
        let res = req
            .send()
            .await
            .with_context(|| format!("get params {}", prefix))?;
        if let Some(ps) = res.parameters {
            all.extend(ps);
        }
        match res.next_token {
            Some(t) => next = Some(t),
            None => break,
        }
    }
    Ok(all)
}

/// タグフィルタで parameter name を取得。path_prefix を渡すと SSM 側で prefix 絞り込み
/// (Path + Recursive) を併用し、クライアント側の post-filter を不要にする。
pub async fn names_filtered_by_tags(
    client: &Client,
    tag_filters: &[(String, String)],
    path_prefix: Option<&str>,
) -> Result<Vec<String>> {
    let mut filters: Vec<ParameterStringFilter> = Vec::with_capacity(tag_filters.len() + 1);
    if let Some(p) = path_prefix {
        filters.push(
            ParameterStringFilter::builder()
                .key("Path")
                .option("Recursive")
                .values(p)
                .build()
                .map_err(|e| anyhow!("build Path filter: {}", e))?,
        );
    }
    for (k, v) in tag_filters {
        filters.push(
            ParameterStringFilter::builder()
                .key(format!("tag:{}", k))
                .option("Equals")
                .values(v.clone())
                .build()
                .map_err(|e| anyhow!("build tag filter: {}", e))?,
        );
    }

    let mut names = Vec::new();
    let mut next: Option<String> = None;
    loop {
        let mut req = client
            .describe_parameters()
            .set_parameter_filters(Some(filters.clone()));
        if let Some(t) = &next {
            req = req.next_token(t);
        }
        let res = req
            .send()
            .await
            .context("describe_parameters with filters")?;
        if let Some(ps) = res.parameters {
            names.extend(ps.into_iter().filter_map(|p| p.name));
        }
        match res.next_token {
            Some(t) => next = Some(t),
            None => break,
        }
    }
    Ok(names)
}

pub async fn get_parameters_by_names(client: &Client, names: &[String]) -> Result<Vec<Parameter>> {
    if names.is_empty() {
        return Ok(Vec::new());
    }
    let futs = names.chunks(10).map(|chunk| {
        let chunk = chunk.to_vec();
        async move {
            client
                .get_parameters()
                .set_names(Some(chunk))
                .with_decryption(true)
                .send()
                .await
                .context("get_parameters")
        }
    });
    let results = run_bounded(futs, read_concurrency()).await?;
    Ok(results
        .into_iter()
        .flat_map(|r| r.parameters.unwrap_or_default())
        .collect())
}

pub async fn delete_parameters_batched(client: &Client, names: &[String]) -> Result<Vec<String>> {
    if names.is_empty() {
        return Ok(Vec::new());
    }
    let futs = names.chunks(10).map(|chunk| {
        let chunk = chunk.to_vec();
        async move {
            client
                .delete_parameters()
                .set_names(Some(chunk))
                .send()
                .await
                .context("delete_parameters")
        }
    });
    let results = run_bounded(futs, write_concurrency()).await?;
    Ok(results
        .into_iter()
        .flat_map(|r| r.deleted_parameters.unwrap_or_default())
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssm_name_to_env_key_basic() {
        assert_eq!(
            ssm_name_to_env_key("/myteam/my-app/kintone-id", "/myteam/my-app"),
            "KINTONE_ID"
        );
    }

    #[test]
    fn ssm_name_to_env_key_nested_segments() {
        assert_eq!(
            ssm_name_to_env_key("/myteam/my-app/nested/segment/api-key", "/myteam/my-app"),
            "NESTED_SEGMENT_API_KEY"
        );
    }

    #[test]
    fn ssm_name_to_env_key_from_root_strips_app() {
        assert_eq!(
            ssm_name_to_env_key_from_root("/myteam/app-name/kintone-id", "/myteam"),
            "KINTONE_ID"
        );
        assert_eq!(
            ssm_name_to_env_key_from_root("/myteam/my-app/nested/segment/api-key", "/myteam"),
            "NESTED_SEGMENT_API_KEY"
        );
        // root が異なっても動作
        assert_eq!(
            ssm_name_to_env_key_from_root("/myteam/foo/bar-baz", "/myteam"),
            "BAR_BAZ"
        );
    }

    #[test]
    fn env_key_to_ssm_tail_lowercases_and_dasheses() {
        assert_eq!(env_key_to_ssm_tail("KINTONE_API_TOKEN"), "kintone-api-token");
        assert_eq!(env_key_to_ssm_tail("PTOWN_PASS"), "ptown-pass");
        assert_eq!(env_key_to_ssm_tail("A"), "a");
    }

    #[test]
    fn should_be_secure_default_true() {
        assert!(should_be_secure("KINTONE_API_TOKEN"));
        assert!(should_be_secure("SLACK_BOT_TOKEN"));
        assert!(should_be_secure("SOMETHING_UNKNOWN"));
        assert!(should_be_secure("PTOWN_USERNAME"));
    }

    #[test]
    fn should_be_secure_url_keys_are_secure() {
        // v0.1.1: `_url` suffix はもはや safe list に無い。
        // URL は credentials を含む可能性が高いため SecureString デフォルト
        assert!(should_be_secure("DATABASE_URL"));
        assert!(should_be_secure("POSTGRES_URL"));
        assert!(should_be_secure("SLACK_WEBHOOK_URL"));
        assert!(should_be_secure("GOOGLE_SPREADSHEET_URL"));
        assert!(should_be_secure("SENTRY_DSN"));
    }

    #[test]
    fn should_be_secure_public_suffixes_map_to_string() {
        assert!(!should_be_secure("GOOGLE_CREDENTIALS_PATH"));
        assert!(!should_be_secure("SLACK_CHANNEL"));
        assert!(!should_be_secure("DB_HOST"));
        assert!(!should_be_secure("HTTP_PORT"));
        assert!(!should_be_secure("AWS_REGION"));
        assert!(!should_be_secure("LOG_DIR"));
        assert!(!should_be_secure("API_ENDPOINT"));
    }
}
