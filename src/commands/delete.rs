use anyhow::{Context, Result};
use aws_sdk_ssm::Client;
use colored::Colorize;

use crate::app::{app_prefix, resolve_app};
use crate::ssm::{delete_parameters_batched, env_key_to_ssm_tail, get_parameters_by_path};
use crate::util::confirm_prompt;

pub async fn cmd_delete(
    client: &Client,
    target: String,
    app: Option<String>,
    yes: bool,
    recursive: bool,
) -> Result<()> {
    let absolute = if target.starts_with('/') {
        target.clone()
    } else {
        format!(
            "{}/{}",
            app_prefix(&resolve_app(app)?),
            env_key_to_ssm_tail(&target)
        )
    };

    if recursive {
        let params = get_parameters_by_path(client, &absolute).await?;
        if params.is_empty() {
            println!("(no parameters under {})", absolute);
            return Ok(());
        }
        println!(
            "about to delete {} parameters under {}:",
            params.len(),
            absolute.bold()
        );
        for p in &params {
            println!("  - {}", p.name().unwrap_or_default());
        }
        if !yes && !confirm_prompt("proceed?")? {
            println!("aborted.");
            return Ok(());
        }
        let names: Vec<String> = params
            .iter()
            .filter_map(|p| p.name().map(|s| s.to_string()))
            .collect();
        let deleted = delete_parameters_batched(client, &names).await?;
        for n in deleted {
            println!("  ✓ deleted {}", n);
        }
    } else {
        println!("delete {}", absolute.bold());
        if !yes && !confirm_prompt("proceed?")? {
            println!("aborted.");
            return Ok(());
        }
        client
            .delete_parameter()
            .name(&absolute)
            .send()
            .await
            .with_context(|| format!("delete {}", absolute))?;
        println!("  ✓ deleted {}", absolute);
    }
    Ok(())
}
