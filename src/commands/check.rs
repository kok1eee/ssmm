use anyhow::Result;
use aws_sdk_ssm::Client;
use colored::Colorize;
use std::collections::BTreeMap;

use crate::config::prefix_root;
use crate::ssm::get_parameters_by_path;
use crate::util::hash8;

pub async fn cmd_check(
    client: &Client,
    duplicates: bool,
    values: bool,
    show_values: bool,
) -> Result<()> {
    if !duplicates && !values {
        println!("(nothing to check; pass --duplicates and/or --values)");
        return Ok(());
    }

    let params = get_parameters_by_path(client, prefix_root()).await?;
    if params.is_empty() {
        println!("(no parameters under {})", prefix_root());
        return Ok(());
    }

    if duplicates {
        let prefix_slash = format!("{}/", prefix_root());
        let mut by_tail: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for p in &params {
            let name = p.name().unwrap_or_default();
            let rest = name.strip_prefix(&prefix_slash).unwrap_or(name);
            let (app, tail) = rest.split_once('/').unwrap_or((rest, ""));
            by_tail
                .entry(tail.to_string())
                .or_default()
                .push(app.to_string());
        }
        println!("{}", "[key-name duplicates]".bold());
        let groups: Vec<_> = by_tail.iter().filter(|(_, apps)| apps.len() >= 2).collect();
        if groups.is_empty() {
            println!("  no duplicates.");
        } else {
            for (tail, apps) in groups {
                println!(
                    "  {}: {} [{} apps]",
                    tail.yellow().bold(),
                    apps.join(", "),
                    apps.len()
                );
            }
        }
    }

    if values {
        if duplicates {
            println!();
        }
        println!("{}", "[value duplicates]".bold());
        let mut by_value: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for p in &params {
            let name = p.name().unwrap_or_default().to_string();
            let value = p.value().unwrap_or_default().to_string();
            by_value.entry(value).or_default().push(name);
        }
        let groups: Vec<_> = by_value
            .iter()
            .filter(|(_, names)| names.len() >= 2)
            .collect();
        if groups.is_empty() {
            println!("  no value duplicates.");
        } else {
            for (value, names) in groups {
                let display = if show_values {
                    value.clone()
                } else {
                    format!("sha256={} len={}", hash8(value), value.len())
                };
                println!("  {} [{} parameters]", display.yellow().bold(), names.len());
                for n in names {
                    println!("    - {}", n);
                }
            }
        }
    }

    Ok(())
}
