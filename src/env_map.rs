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
    /// 各 app の (name, fetched_count) を指定順で保持。単一 app 時は len=1。
    pub app_params_counts: Vec<(String, usize)>,
    pub shared_params_count: usize,
    pub tag_params_count: usize,
}

impl MergedEnv {
    /// ログ用フォーマット: 単一なら `app=5`、複数なら `apps=common:17,soumu:3`
    pub fn apps_label(&self) -> String {
        match self.app_params_counts.as_slice() {
            [] => "app=0".to_string(),
            [(_, n)] => format!("app={}", n),
            many => {
                let parts: Vec<String> = many.iter().map(|(n, c)| format!("{}:{}", n, c)).collect();
                format!("apps={}", parts.join(","))
            }
        }
    }
}

/// 優先度 apps[N..0] > include-tag > shared で SSM を畳み込み、env key → value に正規化。
/// 同じ key が複数 app にある場合は、引数順の後ろ側 (apps[N]) が勝つ (last wins)。
/// `strict=true` のとき layer 間衝突があれば bail、false のときは stderr 警告のみ。
pub async fn build_env_map(
    client: &Client,
    apps: &[String],
    no_shared: bool,
    include_tags: &[(String, String)],
    strict: bool,
) -> Result<MergedEnv> {
    if apps.is_empty() {
        bail!("build_env_map called with empty apps (internal error)");
    }

    // shared overlay は「app=shared を明示指定した」ケースでのみ抑制
    let want_shared = !no_shared && !apps.iter().any(|a| a == "shared");

    let app_prefixes: Vec<String> = apps.iter().map(|a| app_prefix(a)).collect();

    // 各 app の fetch + shared + tag_names を並列化 (hot path)
    let app_fetches =
        futures::future::try_join_all(app_prefixes.iter().map(|p| get_parameters_by_path(client, p)));
    let (apps_params, shared_params, tag_names) = tokio::try_join!(
        app_fetches,
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
    let already: HashSet<&str> = apps_params
        .iter()
        .flatten()
        .chain(shared_params.iter())
        .filter_map(|p| p.name())
        .collect();
    let tag_param_names: Vec<String> = tag_names
        .into_iter()
        .filter(|n| !already.contains(n.as_str()))
        .collect();
    let tag_params = get_parameters_by_names(client, &tag_param_names).await?;

    let all_apps_empty = apps_params.iter().all(|p| p.is_empty());
    if all_apps_empty && shared_params.is_empty() && tag_params.is_empty() {
        bail!(
            "no parameters found (apps={:?}, shared={}, include-tags={:?})",
            apps,
            want_shared,
            include_tags
        );
    }

    // ingest 順: shared → tag → apps[0] → apps[1] → ... → apps[N-1]
    // (後勝ち。同一 key は後で insert したレイヤで上書きされる)
    let mut merged: BTreeMap<String, String> = BTreeMap::new();
    let mut shared_keys: HashSet<String> = HashSet::new();
    let mut tag_keys: HashSet<String> = HashSet::new();
    // 各 app が投入した key の集合 (conflict 検出用)
    let mut per_app_keys: Vec<(String, HashSet<String>)> = Vec::with_capacity(apps.len());

    for p in &shared_params {
        let key = ssm_name_to_env_key(p.name().unwrap_or_default(), shared_prefix());
        let value = p.value().unwrap_or_default().to_string();
        shared_keys.insert(key.clone());
        merged.insert(key, value);
    }
    for p in &tag_params {
        let key = ssm_name_to_env_key_from_root(p.name().unwrap_or_default(), prefix_root());
        let value = p.value().unwrap_or_default().to_string();
        tag_keys.insert(key.clone());
        merged.insert(key, value);
    }
    for (i, params) in apps_params.iter().enumerate() {
        let prefix = &app_prefixes[i];
        let mut this_app_keys: HashSet<String> = HashSet::new();
        for p in params {
            let key = ssm_name_to_env_key(p.name().unwrap_or_default(), prefix);
            let value = p.value().unwrap_or_default().to_string();
            this_app_keys.insert(key.clone());
            merged.insert(key, value);
        }
        per_app_keys.push((apps[i].clone(), this_app_keys));
    }

    // conflict 検出: shared/tag が後続 app に上書きされたか、app[i] が app[j>i] に上書きされたか
    let union_app_keys: HashSet<&String> = per_app_keys
        .iter()
        .flat_map(|(_, s)| s.iter())
        .collect();

    let shared_by_app: Vec<&String> = union_app_keys
        .iter()
        .filter(|k| shared_keys.contains(k.as_str()))
        .copied()
        .collect();
    let tag_by_app: Vec<&String> = union_app_keys
        .iter()
        .filter(|k| tag_keys.contains(k.as_str()) && !shared_keys.contains(k.as_str()))
        .copied()
        .collect();

    // app 同士の上書き: apps[j] (j>i) が apps[i] の key を持っていたら conflict
    // 報告形式: "key (app_a -> app_b)"
    let mut inter_app_conflicts: Vec<String> = Vec::new();
    for i in 0..per_app_keys.len() {
        for j in (i + 1)..per_app_keys.len() {
            let (ni, si) = &per_app_keys[i];
            let (nj, sj) = &per_app_keys[j];
            let mut shared: Vec<&String> = si.intersection(sj).collect();
            shared.sort();
            for k in shared {
                inter_app_conflicts.push(format!("{} ({} <- {})", k, ni, nj));
            }
        }
    }

    let label = if strict {
        "error:".red().bold()
    } else {
        "warning:".yellow().bold()
    };
    let mut total_conflicts = 0usize;

    if !shared_by_app.is_empty() {
        let mut names: Vec<&str> = shared_by_app.iter().map(|s| s.as_str()).collect();
        names.sort();
        names.dedup();
        total_conflicts += names.len();
        eprintln!(
            "{} {} shared key(s) overridden by app: {}",
            label,
            names.len(),
            names.join(", ")
        );
    }
    if !tag_by_app.is_empty() {
        let mut names: Vec<&str> = tag_by_app.iter().map(|s| s.as_str()).collect();
        names.sort();
        names.dedup();
        total_conflicts += names.len();
        eprintln!(
            "{} {} tag key(s) overridden by app: {}",
            label,
            names.len(),
            names.join(", ")
        );
    }
    if !inter_app_conflicts.is_empty() {
        total_conflicts += inter_app_conflicts.len();
        eprintln!(
            "{} {} app key(s) overridden by later --app: {}",
            label,
            inter_app_conflicts.len(),
            inter_app_conflicts.join(", ")
        );
    }

    if strict && total_conflicts > 0 {
        bail!(
            "aborted by --strict due to {} conflict(s)",
            total_conflicts
        );
    }

    let app_params_counts = apps
        .iter()
        .zip(apps_params.iter())
        .map(|(name, ps)| (name.clone(), ps.len()))
        .collect();

    Ok(MergedEnv {
        map: merged,
        app_params_counts,
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
    fn apps_label_single() {
        let me = MergedEnv {
            map: BTreeMap::new(),
            app_params_counts: vec![("hikken-schedule".to_string(), 5)],
            shared_params_count: 0,
            tag_params_count: 0,
        };
        assert_eq!(me.apps_label(), "app=5");
    }

    #[test]
    fn apps_label_multiple() {
        let me = MergedEnv {
            map: BTreeMap::new(),
            app_params_counts: vec![
                ("knowledge-bot-common".to_string(), 17),
                ("knowledge-bot-soumu".to_string(), 3),
            ],
            shared_params_count: 0,
            tag_params_count: 0,
        };
        assert_eq!(me.apps_label(), "apps=knowledge-bot-common:17,knowledge-bot-soumu:3");
    }

    #[test]
    fn apps_label_empty() {
        let me = MergedEnv {
            map: BTreeMap::new(),
            app_params_counts: vec![],
            shared_params_count: 0,
            tag_params_count: 0,
        };
        assert_eq!(me.apps_label(), "app=0");
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
