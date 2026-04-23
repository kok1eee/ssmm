use anyhow::{Context, Result, bail};
use aws_sdk_ssm::Client;
use aws_sdk_ssm::types::{ParameterTier, ParameterType, ResourceTypeForTagging};
use colored::Colorize;
use std::collections::HashSet;
use std::path::PathBuf;

use crate::app::{app_prefix, resolve_app};
use crate::config::{advanced_tier, kms_key_id, write_concurrency};
use crate::env_map::{parse_kv_pairs, parse_tags, read_env_file};
use crate::ssm::{build_param_name, build_tags, resolve_type};
use crate::util::run_bounded;

/// Put a pre-parsed, pre-filtered batch of (key, value) pairs to SSM under
/// `/<prefix_root>/<app>/`. cmd_put is the CLI shim over this; cmd_onboard
/// calls it directly to avoid re-reading and re-filtering the .env file.
pub async fn put_kvs(
    client: &Client,
    kvs: &[(String, String)],
    app: &str,
    plain_all: bool,
    plain_set: &HashSet<String>,
    secure_set: &HashSet<String>,
    extra_tags: &[(String, String)],
) -> Result<()> {
    let prefix = app_prefix(app);

    let app_tag_pair = vec![("app".to_string(), app.to_string())];
    let all_tags: Vec<(String, String)> = app_tag_pair
        .into_iter()
        .chain(extra_tags.iter().cloned())
        .collect();

    let futs = kvs.iter().map(|(k, v)| {
        let name = build_param_name(&prefix, k);
        let (ptype, reason) = resolve_type(k, plain_all, plain_set, secure_set);
        let tags = all_tags.clone();
        let key = k.clone();
        let value = v.clone();
        async move {
            let tag_objs = build_tags(&tags)?;
            let mut req = client
                .put_parameter()
                .name(&name)
                .value(&value)
                .r#type(ptype.clone())
                .overwrite(true);
            if advanced_tier() {
                req = req.tier(ParameterTier::Advanced);
            }
            if matches!(ptype, ParameterType::SecureString)
                && let Some(k) = kms_key_id()
            {
                req = req.key_id(k);
            }
            req.send()
                .await
                .with_context(|| format!("put-parameter {}", name))?;

            if let Err(e) = client
                .add_tags_to_resource()
                .resource_type(ResourceTypeForTagging::Parameter)
                .resource_id(&name)
                .set_tags(Some(tag_objs))
                .send()
                .await
            {
                eprintln!(
                    "  {} tag failed for {}: {}",
                    "warning:".yellow().bold(),
                    name,
                    e
                );
            }

            Ok::<_, anyhow::Error>((name, ptype, reason, key, value.len()))
        }
    });
    let results = run_bounded(futs, write_concurrency()).await?;

    let tag_note = if extra_tags.is_empty() {
        String::new()
    } else {
        format!(
            " +tags[{}]",
            extra_tags
                .iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect::<Vec<_>>()
                .join(",")
        )
    };
    for (name, ptype, reason, _key, len) in results {
        let type_label = match ptype {
            ParameterType::SecureString => "SecureString".yellow(),
            _ => "String".green(),
        };
        println!(
            "  ✓ {} ({} [{}], len={}){}",
            name,
            type_label,
            reason.label().dimmed(),
            len,
            tag_note
        );
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn cmd_put(
    client: &Client,
    pairs: Vec<String>,
    env: Option<PathBuf>,
    app: Option<String>,
    plain_all: bool,
    plain_keys: Vec<String>,
    secure_keys: Vec<String>,
    raw_tags: Vec<String>,
) -> Result<()> {
    let app = resolve_app(app)?;

    let mut kvs: Vec<(String, String)> = if let Some(path) = env {
        read_env_file(&path)?
    } else if !pairs.is_empty() {
        parse_kv_pairs(&pairs)?
    } else {
        bail!("either --env <file> or KEY=VALUE arguments are required");
    };
    let before = kvs.len();
    kvs.retain(|(k, v)| {
        if v.is_empty() {
            eprintln!(
                "  {} empty value, skipped: {}",
                "warning:".yellow().bold(),
                k
            );
            false
        } else {
            true
        }
    });
    if kvs.len() < before {
        eprintln!(
            "  ({} key(s) skipped due to empty value)",
            before - kvs.len()
        );
    }
    if kvs.is_empty() {
        bail!("no key=value to put");
    }

    let plain_set: HashSet<String> = plain_keys.into_iter().collect();
    let secure_set: HashSet<String> = secure_keys.into_iter().collect();
    if let Some(conflict) = plain_set.intersection(&secure_set).next() {
        bail!(
            "key {:?} is listed in both --plain-key and --secure; pick one",
            conflict
        );
    }

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
