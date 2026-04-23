use anyhow::Result;
use aws_sdk_ssm::Client;
use aws_sdk_ssm::types::ParameterType;
use colored::Colorize;
use std::collections::BTreeMap;

use crate::config::prefix_root;
use crate::ssm::get_parameters_by_path;

pub async fn cmd_dirs(client: &Client) -> Result<()> {
    let params = get_parameters_by_path(client, prefix_root()).await?;
    let prefix_slash = format!("{}/", prefix_root());
    let mut by_app: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    for p in &params {
        let name = p.name().unwrap_or_default();
        let rest = name.strip_prefix(&prefix_slash).unwrap_or(name);
        let app = rest.split('/').next().unwrap_or(rest).to_string();
        let entry = by_app.entry(app).or_insert((0, 0));
        entry.0 += 1;
        if matches!(p.r#type(), Some(&ParameterType::SecureString)) {
            entry.1 += 1;
        }
    }
    if by_app.is_empty() {
        println!("(no parameters under {})", prefix_root());
        return Ok(());
    }
    println!(
        "{:<32} {:>6} {:>8}",
        "app".bold(),
        "total".bold(),
        "secure".bold()
    );
    for (app, (total, secure)) in by_app {
        println!("{:<32} {:>6} {:>8}", app, total, secure);
    }
    Ok(())
}
