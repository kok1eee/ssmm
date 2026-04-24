use anyhow::{Context, Result};
use aws_sdk_ssm::Client;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use crate::app::resolve_apps;
use crate::env_map::{build_env_map, parse_tags};

pub async fn cmd_sync(
    client: &Client,
    apps: Vec<String>,
    out: PathBuf,
    no_shared: bool,
    raw_include_tags: Vec<String>,
    strict: bool,
) -> Result<()> {
    let apps = resolve_apps(apps)?;
    let include_tags = parse_tags(&raw_include_tags)?;
    let merged = build_env_map(client, &apps, no_shared, &include_tags, strict).await?;

    let body: String = merged
        .map
        .iter()
        .map(|(k, v)| format!("{}={}\n", k, v))
        .collect();

    let existing = std::fs::read_to_string(&out).ok();
    if existing.as_deref() == Some(body.as_str()) {
        println!(
            "ssmm: no change ({} variables; {}, shared={}, tag={})",
            merged.map.len(),
            merged.apps_label(),
            merged.shared_params_count,
            merged.tag_params_count
        );
        return Ok(());
    }

    let tmp = out.with_extension("env.tmp");
    std::fs::write(&tmp, &body).with_context(|| format!("write {}", tmp.display()))?;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    std::fs::rename(&tmp, &out)?;
    println!(
        "ssmm: wrote {} variables to {} ({}, shared={}, tag={})",
        merged.map.len(),
        out.display(),
        merged.apps_label(),
        merged.shared_params_count,
        merged.tag_params_count
    );
    Ok(())
}
