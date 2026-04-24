use anyhow::Result;
use aws_sdk_ssm::Client;
use aws_sdk_ssm::types::{Parameter, ParameterType};
use colored::Colorize;
use std::collections::BTreeMap;

use crate::app::{app_prefix, resolve_apps};
use crate::config::prefix_root;
use crate::env_map::parse_tags;
use crate::ssm::{
    get_parameters_by_names, get_parameters_by_path, names_filtered_by_tags, ssm_name_to_env_key,
    ssm_name_to_env_key_from_root,
};
use crate::util::print_entry;

pub async fn cmd_list(
    client: &Client,
    apps: Vec<String>,
    all: bool,
    keys_only: bool,
    raw_tags: Vec<String>,
) -> Result<()> {
    let tag_filters = parse_tags(&raw_tags)?;

    // --all は apps/--app を無視して prefix 全体を単一スコープで表示
    if all {
        let prefix = prefix_root().to_string();
        let params = fetch_params(client, &prefix, &tag_filters).await?;
        if params.is_empty() {
            println!("(no parameters under {})", prefix.dimmed());
            return Ok(());
        }
        print_by_app(&params, keys_only);
        return Ok(());
    }

    let apps = resolve_apps(apps)?;

    if apps.len() == 1 {
        // 従来挙動: 単一 app の flat リスト
        let prefix = app_prefix(&apps[0]);
        let params = fetch_params(client, &prefix, &tag_filters).await?;
        if params.is_empty() {
            println!("(no parameters under {})", prefix.dimmed());
            return Ok(());
        }
        let mut entries: Vec<(String, String, bool)> = params
            .iter()
            .map(|p| {
                let key = ssm_name_to_env_key(p.name().unwrap_or_default(), &prefix);
                let value = p.value().unwrap_or_default().to_string();
                let secure = matches!(p.r#type(), Some(&ParameterType::SecureString));
                (key, value, secure)
            })
            .collect();
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        println!(
            "{}",
            format!("# {} ({} variables)", prefix, entries.len()).dimmed()
        );
        for (k, v, secure) in entries {
            print_entry(&k, Some(&v), secure, keys_only, "");
        }
        return Ok(());
    }

    // 複数 app: 各 app を [app] セクションで区切って表示 (--all の scoped 版)
    for app in &apps {
        let prefix = app_prefix(app);
        let params = fetch_params(client, &prefix, &tag_filters).await?;
        println!("{}", format!("[{}]", app).bold().cyan());
        if params.is_empty() {
            println!("  {}", "(no parameters)".dimmed());
            continue;
        }
        let mut entries: Vec<(String, String, bool)> = params
            .iter()
            .map(|p| {
                let key = ssm_name_to_env_key(p.name().unwrap_or_default(), &prefix);
                let value = p.value().unwrap_or_default().to_string();
                let secure = matches!(p.r#type(), Some(&ParameterType::SecureString));
                (key, value, secure)
            })
            .collect();
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        for (k, v, secure) in entries {
            print_entry(&k, Some(&v), secure, keys_only, "  ");
        }
    }
    Ok(())
}

async fn fetch_params(
    client: &Client,
    prefix: &str,
    tag_filters: &[(String, String)],
) -> Result<Vec<Parameter>> {
    if tag_filters.is_empty() {
        get_parameters_by_path(client, prefix).await
    } else {
        let names = names_filtered_by_tags(client, tag_filters, Some(prefix)).await?;
        if names.is_empty() {
            return Ok(Vec::new());
        }
        get_parameters_by_names(client, &names).await
    }
}

fn print_by_app(params: &[Parameter], keys_only: bool) {
    let prefix_slash = format!("{}/", prefix_root());
    let mut by_app: BTreeMap<String, Vec<(String, String, bool)>> = BTreeMap::new();
    for p in params {
        let name = p.name().unwrap_or_default();
        let rest = name.strip_prefix(&prefix_slash).unwrap_or(name);
        let (app_name, _) = rest.split_once('/').unwrap_or((rest, ""));
        let key = ssm_name_to_env_key_from_root(name, prefix_root());
        let value = p.value().unwrap_or_default().to_string();
        let secure = matches!(p.r#type(), Some(&ParameterType::SecureString));
        by_app
            .entry(app_name.to_string())
            .or_default()
            .push((key, value, secure));
    }
    for (app_name, mut entries) in by_app {
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        println!("{}", format!("[{}]", app_name).bold().cyan());
        for (k, v, secure) in entries {
            print_entry(&k, Some(&v), secure, keys_only, "  ");
        }
    }
}
