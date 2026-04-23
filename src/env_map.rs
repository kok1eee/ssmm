use anyhow::{Context, Result, anyhow, bail};
use aws_sdk_ssm::Client;
use colored::Colorize;
use std::collections::{BTreeMap, HashSet};
use std::path::Path;

use crate::app::app_prefix;
use crate::config::{prefix_root, shared_prefix};
use crate::ssm::{
    get_parameters_by_names, get_parameters_by_path, names_filtered_by_tags, ssm_name_to_env_key,
    ssm_name_to_env_key_from_root,
};

pub fn read_env_file(path: &Path) -> Result<Vec<(String, String)>> {
    let content =
        std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let mut out = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            let v = v.trim();
            let v = v
                .strip_prefix('"')
                .and_then(|s| s.strip_suffix('"'))
                .unwrap_or(v);
            let v = v
                .strip_prefix('\'')
                .and_then(|s| s.strip_suffix('\''))
                .unwrap_or(v);
            out.push((k.trim().to_string(), v.to_string()));
        }
    }
    Ok(out)
}

pub fn parse_kv_pairs(pairs: &[String]) -> Result<Vec<(String, String)>> {
    pairs
        .iter()
        .map(|p| {
            p.split_once('=')
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .ok_or_else(|| anyhow!("invalid KEY=VALUE: {}", p))
        })
        .collect()
}

pub fn parse_tags(raw: &[String]) -> Result<Vec<(String, String)>> {
    raw.iter()
        .map(|s| {
            s.split_once('=')
                .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
                .ok_or_else(|| anyhow!("invalid tag (need KEY=VALUE): {}", s))
        })
        .collect()
}

/// sync と exec で共有する、app + shared + tag overlay を畳み込んだ環境マップ。
pub struct MergedEnv {
    pub map: BTreeMap<String, String>,
    pub app_params_count: usize,
    pub shared_params_count: usize,
    pub tag_params_count: usize,
}

/// 優先度 app > include-tag > shared で SSM を畳み込み、env key → value に正規化する。
/// `strict=true` のとき shared/app 衝突があれば bail、false のときは stderr 警告のみ。
pub async fn build_env_map(
    client: &Client,
    app: &str,
    no_shared: bool,
    include_tags: &[(String, String)],
    strict: bool,
) -> Result<MergedEnv> {
    let prefix = app_prefix(app);
    let want_shared = !no_shared && app != "shared";

    // 3 本の SSM 問い合わせを並列化 (hot path)
    let (app_params, shared_params, tag_names) = tokio::try_join!(
        get_parameters_by_path(client, &prefix),
        async {
            if want_shared {
                get_parameters_by_path(client, shared_prefix()).await
            } else {
                Ok(Vec::new())
            }
        },
        async {
            if include_tags.is_empty() {
                Ok(Vec::new())
            } else {
                names_filtered_by_tags(client, include_tags, Some(prefix_root())).await
            }
        }
    )?;

    // tag_names から app/shared と重複する name を除いた残りを取得
    let already: HashSet<&str> = app_params
        .iter()
        .chain(shared_params.iter())
        .filter_map(|p| p.name())
        .collect();
    let tag_param_names: Vec<String> = tag_names
        .into_iter()
        .filter(|n| !already.contains(n.as_str()))
        .collect();
    let tag_params = get_parameters_by_names(client, &tag_param_names).await?;

    if app_params.is_empty() && shared_params.is_empty() && tag_params.is_empty() {
        bail!(
            "no parameters found (app={}, shared={}, include-tags={:?})",
            app,
            want_shared,
            include_tags
        );
    }

    // 優先度: app > include-tag > shared
    // 同じ env key を後から上書き → app が最後に入るよう shared → tag → app の順で ingest
    let mut merged: BTreeMap<String, String> = BTreeMap::new();
    let mut shared_keys: HashSet<String> = HashSet::new();
    let mut app_keys: HashSet<String> = HashSet::new();

    for p in &shared_params {
        let key = ssm_name_to_env_key(p.name().unwrap_or_default(), shared_prefix());
        let value = p.value().unwrap_or_default().to_string();
        shared_keys.insert(key.clone());
        merged.insert(key, value);
    }
    for p in &tag_params {
        let key = ssm_name_to_env_key_from_root(p.name().unwrap_or_default(), prefix_root());
        let value = p.value().unwrap_or_default().to_string();
        merged.insert(key, value);
    }
    for p in &app_params {
        let key = ssm_name_to_env_key(p.name().unwrap_or_default(), &prefix);
        let value = p.value().unwrap_or_default().to_string();
        app_keys.insert(key.clone());
        merged.insert(key, value);
    }

    let conflicts: Vec<&String> = app_keys.intersection(&shared_keys).collect();
    if !conflicts.is_empty() {
        let mut names: Vec<&str> = conflicts.iter().map(|s| s.as_str()).collect();
        names.sort();
        let label = if strict {
            "error:".red().bold()
        } else {
            "warning:".yellow().bold()
        };
        eprintln!(
            "{} {} shared key(s) overridden by app: {}",
            label,
            names.len(),
            names.join(", ")
        );
        if strict {
            bail!("aborted by --strict due to {} conflict(s)", names.len());
        }
    }

    Ok(MergedEnv {
        map: merged,
        app_params_count: app_params.len(),
        shared_params_count: shared_params.len(),
        tag_params_count: tag_params.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as IoWrite;
    use tempfile::NamedTempFile;

    #[test]
    fn parse_tags_basic() {
        let tags = parse_tags(&["env=prod".to_string(), "owner=backend".to_string()]).unwrap();
        assert_eq!(
            tags,
            vec![
                ("env".to_string(), "prod".to_string()),
                ("owner".to_string(), "backend".to_string()),
            ]
        );
    }

    #[test]
    fn parse_tags_trims_whitespace() {
        let tags = parse_tags(&["  env = prod  ".to_string()]).unwrap();
        assert_eq!(tags, vec![("env".to_string(), "prod".to_string())]);
    }

    #[test]
    fn parse_tags_rejects_missing_equals() {
        let err = parse_tags(&["no-equals".to_string()]).unwrap_err();
        assert!(err.to_string().contains("invalid tag"));
    }

    #[test]
    fn parse_kv_pairs_basic() {
        let pairs = parse_kv_pairs(&["A=1".to_string(), "B=2".to_string()]).unwrap();
        assert_eq!(
            pairs,
            vec![
                ("A".to_string(), "1".to_string()),
                ("B".to_string(), "2".to_string()),
            ]
        );
    }

    #[test]
    fn parse_kv_pairs_value_with_equals_sign() {
        // split_once: 最初の '=' までで分割。値内の '=' は保持
        let pairs = parse_kv_pairs(&["URL=https://a.com?x=y".to_string()]).unwrap();
        assert_eq!(
            pairs,
            vec![("URL".to_string(), "https://a.com?x=y".to_string())]
        );
    }

    #[test]
    fn read_env_file_handles_comments_blanks_quotes() {
        let mut f = NamedTempFile::new().unwrap();
        writeln!(f, "# this is a comment").unwrap();
        writeln!(f).unwrap();
        writeln!(f, "KEY1=value1").unwrap();
        writeln!(f, "KEY2=\"quoted\"").unwrap();
        writeln!(f, "KEY3='single'").unwrap();
        writeln!(f, "  KEY4 = trimmed  ").unwrap();
        let result = read_env_file(f.path()).unwrap();
        assert_eq!(
            result,
            vec![
                ("KEY1".to_string(), "value1".to_string()),
                ("KEY2".to_string(), "quoted".to_string()),
                ("KEY3".to_string(), "single".to_string()),
                ("KEY4".to_string(), "trimmed".to_string()),
            ]
        );
    }
}
