use anyhow::{Context, Result};
use aws_sdk_ssm::Client;
use aws_sdk_ssm::types::ParameterType;
use colored::Colorize;

use crate::app::resolve_param_name;

pub async fn cmd_show(client: &Client, key: String, app: Option<String>) -> Result<()> {
    let name = resolve_param_name(&key, app)?;
    let res = client
        .get_parameter()
        .name(&name)
        .with_decryption(true)
        .send()
        .await
        .with_context(|| format!("get {}", name))?;
    if let Some(p) = res.parameter {
        let value = p.value().unwrap_or_default();
        let secure = matches!(p.r#type(), Some(&ParameterType::SecureString));
        let label = if secure {
            "SecureString".yellow()
        } else {
            "String".green()
        };
        println!("# {} ({})", name.dimmed(), label);
        println!("{}", value);
    }
    Ok(())
}
