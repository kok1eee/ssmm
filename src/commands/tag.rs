use anyhow::{Context, Result, bail};
use aws_sdk_ssm::Client;
use aws_sdk_ssm::types::ResourceTypeForTagging;
use colored::Colorize;

use crate::app::resolve_param_name;
use crate::cli::TagAction;
use crate::env_map::parse_tags;
use crate::ssm::build_tags;

pub async fn cmd_tag(client: &Client, action: TagAction) -> Result<()> {
    match action {
        TagAction::Add { key, tags, app } => {
            let name = resolve_param_name(&key, app)?;
            let tag_pairs = parse_tags(&tags)?;
            if tag_pairs.iter().any(|(k, _)| k == "app") {
                bail!("`app` tag is reserved; cannot add via `ssmm tag add`");
            }
            client
                .add_tags_to_resource()
                .resource_type(ResourceTypeForTagging::Parameter)
                .resource_id(&name)
                .set_tags(Some(build_tags(&tag_pairs)?))
                .send()
                .await
                .with_context(|| format!("add tags to {}", name))?;
            println!(
                "  ✓ tagged {} with {}",
                name,
                tag_pairs
                    .iter()
                    .map(|(k, v)| format!("{}={}", k, v))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        TagAction::Remove { key, tag_keys, app } => {
            let name = resolve_param_name(&key, app)?;
            if tag_keys.iter().any(|k| k == "app") {
                bail!("`app` tag is reserved; cannot remove");
            }
            client
                .remove_tags_from_resource()
                .resource_type(ResourceTypeForTagging::Parameter)
                .resource_id(&name)
                .set_tag_keys(Some(tag_keys.clone()))
                .send()
                .await
                .with_context(|| format!("remove tags from {}", name))?;
            println!("  ✓ removed tags {:?} from {}", tag_keys, name);
        }
        TagAction::List { key, app } => {
            let name = resolve_param_name(&key, app)?;
            let res = client
                .list_tags_for_resource()
                .resource_type(ResourceTypeForTagging::Parameter)
                .resource_id(&name)
                .send()
                .await
                .with_context(|| format!("list tags for {}", name))?;
            println!("{}", format!("# {}", name).dimmed());
            let tags = res.tag_list.unwrap_or_default();
            if tags.is_empty() {
                println!("  (no tags)");
            } else {
                for t in tags {
                    println!("  {}={}", t.key, t.value);
                }
            }
        }
    }
    Ok(())
}
