use anyhow::{Context, Result, bail};
use aws_sdk_ssm::Client;
use aws_sdk_ssm::types::{ParameterTier, ParameterType, ResourceTypeForTagging};
use colored::Colorize;
use serde::Serialize;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use crate::config::{advanced_tier, kms_key_id, prefix_root, write_concurrency};
use crate::ssm::{build_tag, delete_parameters_batched, get_parameters_by_path};
use crate::util::run_bounded;

pub async fn cmd_migrate(
    client: &Client,
    old_prefix: String,
    new_prefix: String,
    delete_old: bool,
    confirm: bool,
) -> Result<()> {
    let params = get_parameters_by_path(client, &old_prefix).await?;
    if params.is_empty() {
        bail!("no parameters under {}", old_prefix);
    }
    println!(
        "migrating {} parameters: {} → {}",
        params.len(),
        old_prefix.bold(),
        new_prefix.bold()
    );

    // --delete-old 指定時は、実削除の有無にかかわらず bak dump を先に書く。
    // SSM Parameter Store は soft-delete が無いため、消した後は復旧 API が
    // 存在しない。JSON dump があれば手動復元の手がかりになる。
    let backup_path: Option<PathBuf> = if delete_old {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let path = PathBuf::from(format!("/tmp/ssmm-migrate-backup-{}.json", ts));
        #[derive(Serialize)]
        struct BackupEntry {
            name: String,
            value: String,
            r#type: &'static str,
        }
        let dump: Vec<BackupEntry> = params
            .iter()
            .map(|p| BackupEntry {
                name: p.name().unwrap_or_default().to_string(),
                value: p.value().unwrap_or_default().to_string(),
                r#type: match p.r#type() {
                    Some(&ParameterType::SecureString) => "SecureString",
                    _ => "String",
                },
            })
            .collect();
        let json = serde_json::to_string_pretty(&dump).context("serialize backup")?;
        std::fs::write(&path, &json).with_context(|| format!("write {}", path.display()))?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        println!(
            "  backup: {} parameters dumped to {} (mode 0600)",
            dump.len(),
            path.display()
        );
        Some(path)
    } else {
        None
    };

    let new_app = new_prefix
        .strip_prefix(&format!("{}/", prefix_root()))
        .map(|s| s.split('/').next().unwrap_or(s).to_string());

    let old_prefix_slash = format!("{}/", old_prefix.trim_end_matches('/'));
    let new_prefix_trim = new_prefix.trim_end_matches('/').to_string();

    let futs = params.iter().map(|p| {
        let old_name = p.name().unwrap_or_default().to_string();
        let suffix = old_name
            .strip_prefix(&old_prefix_slash)
            .unwrap_or(&old_name)
            .to_string();
        let new_name = format!("{}/{}", new_prefix_trim, suffix);
        let value = p.value().unwrap_or_default().to_string();
        let ptype = p.r#type().cloned().unwrap_or(ParameterType::String);
        let new_app = new_app.clone();
        async move {
            let mut req = client
                .put_parameter()
                .name(&new_name)
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
                .with_context(|| format!("put {}", new_name))?;
            if let Some(app) = new_app
                && let Err(e) = client
                    .add_tags_to_resource()
                    .resource_type(ResourceTypeForTagging::Parameter)
                    .resource_id(&new_name)
                    .tags(build_tag("app", &app)?)
                    .send()
                    .await
            {
                eprintln!(
                    "  {} tag failed for {}: {}",
                    "warning:".yellow().bold(),
                    new_name,
                    e
                );
            }
            Ok::<_, anyhow::Error>((old_name, new_name))
        }
    });
    let migrated = run_bounded(futs, write_concurrency()).await?;
    for (old, new) in &migrated {
        println!("  ✓ {} → {}", old, new);
    }

    match (delete_old, confirm) {
        (true, true) => {
            let old_names: Vec<String> = migrated.iter().map(|(o, _)| o.clone()).collect();
            println!("deleting {} old parameters...", old_names.len());
            let deleted = delete_parameters_batched(client, &old_names).await?;
            for n in deleted {
                println!("  ✓ deleted {}", n);
            }
            if let Some(p) = backup_path {
                println!(
                    "  {} backup preserved at {} (delete this manually once verified)",
                    "note:".cyan().bold(),
                    p.display()
                );
            }
        }
        (true, false) => {
            eprintln!(
                "{} {} parameters NOT deleted (dry-run). Re-run with `--delete-old --confirm` to delete.",
                "dry-run:".yellow().bold(),
                migrated.len()
            );
            if let Some(p) = backup_path {
                eprintln!("         backup: {}", p.display());
            }
        }
        (false, _) => {
            println!(
                "{} old parameters preserved. Re-run with `--delete-old --confirm` to remove.",
                migrated.len()
            );
        }
    }
    Ok(())
}
