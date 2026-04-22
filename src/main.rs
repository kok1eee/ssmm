use anyhow::{Context, Result, anyhow, bail};
use aws_sdk_ssm::Client;
use aws_sdk_ssm::types::{
    Parameter, ParameterStringFilter, ParameterType, ResourceTypeForTagging, Tag,
};
use clap::{ArgAction, Parser, Subcommand};
use colored::Colorize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::{self, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

const PREFIX_ROOT: &str = "/amu-revo";

#[derive(Parser)]
#[command(name = "ssmm", version, about = "SSM Parameter Store helper for amu-revo team")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// List parameters for an app (CWD auto-detect if no --app)
    List {
        #[arg(long)]
        app: Option<String>,
        /// Show all /amu-revo/* parameters
        #[arg(long)]
        all: bool,
        /// Hide values (show keys only)
        #[arg(long)]
        keys_only: bool,
        /// Filter by tag (repeatable: --tag env=prod --tag owner=backend)
        #[arg(long = "tag", action = ArgAction::Append, value_name = "KEY=VALUE")]
        tags: Vec<String>,
    },
    /// Put parameters from .env or KEY=VALUE pairs
    Put {
        #[arg(value_name = "KEY=VALUE")]
        pairs: Vec<String>,
        /// Read KEY=VALUE pairs from a .env file
        #[arg(long)]
        env: Option<PathBuf>,
        #[arg(long)]
        app: Option<String>,
        /// Force all values to be stored as String (no SecureString auto-detect)
        #[arg(long)]
        plain: bool,
        /// Extra tags (repeatable: --tag env=prod --tag owner=backend)
        /// `app` tag is always attached automatically.
        #[arg(long = "tag", action = ArgAction::Append, value_name = "KEY=VALUE")]
        tags: Vec<String>,
    },
    /// Delete parameters
    Delete {
        target: String,
        #[arg(long)]
        app: Option<String>,
        #[arg(long, short = 'y')]
        yes: bool,
        #[arg(long, short)]
        recursive: bool,
    },
    /// Show a single parameter value
    Show {
        key: String,
        #[arg(long)]
        app: Option<String>,
    },
    /// List all app namespaces under /amu-revo/ with parameter counts
    Dirs,
    /// Sync SSM -> .env (regenerate .env from /amu-revo/<app>/*)
    Sync {
        #[arg(long)]
        app: Option<String>,
        #[arg(long, short, default_value = "./.env")]
        out: PathBuf,
    },
    /// Migrate parameters from an old prefix to a new prefix
    Migrate {
        old_prefix: String,
        new_prefix: String,
        #[arg(long)]
        delete_old: bool,
    },
    /// Check for duplicate keys or identical values across apps
    Check {
        /// Find keys that exist in multiple apps (same trailing key name)
        #[arg(long)]
        duplicates: bool,
        /// Find parameters sharing the same value (candidates for consolidation)
        #[arg(long)]
        values: bool,
        /// Reveal actual values in --values output (default: SHA-256 prefix only)
        #[arg(long)]
        show_values: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let client = Client::new(&config);

    match cli.command {
        Command::List { app, all, keys_only, tags } => {
            cmd_list(&client, app, all, keys_only, tags).await
        }
        Command::Put { pairs, env, app, plain, tags } => {
            cmd_put(&client, pairs, env, app, plain, tags).await
        }
        Command::Delete { target, app, yes, recursive } => {
            cmd_delete(&client, target, app, yes, recursive).await
        }
        Command::Show { key, app } => cmd_show(&client, key, app).await,
        Command::Dirs => cmd_dirs(&client).await,
        Command::Sync { app, out } => cmd_sync(&client, app, out).await,
        Command::Migrate { old_prefix, new_prefix, delete_old } => {
            cmd_migrate(&client, old_prefix, new_prefix, delete_old).await
        }
        Command::Check { duplicates, values, show_values } => {
            cmd_check(&client, duplicates, values, show_values).await
        }
    }
}

// ---------- helpers ----------

fn detect_app_from_cwd() -> Result<String> {
    let pwd = std::env::current_dir()?;
    let name = pwd
        .file_name()
        .ok_or_else(|| anyhow!("cannot determine CWD basename"))?
        .to_string_lossy()
        .into_owned();
    Ok(snake_to_dash(&name))
}

fn snake_to_dash(s: &str) -> String {
    s.replace('_', "-")
}

fn app_prefix(app: &str) -> String {
    format!("{}/{}", PREFIX_ROOT, app)
}

fn ssm_name_to_env_key(name: &str, prefix: &str) -> String {
    let trimmed_prefix = format!("{}/", prefix.trim_end_matches('/'));
    let rest = name.strip_prefix(&trimmed_prefix).unwrap_or(name);
    rest.replace(['/', '-'], "_").to_uppercase()
}

fn env_key_to_ssm_tail(key: &str) -> String {
    key.to_lowercase().replace('_', "-")
}

fn should_be_secure(key: &str) -> bool {
    let lc = key.to_lowercase();
    if lc.contains("webhook") {
        return true;
    }
    const NON_SECRET_SUFFIXES: &[&str] = &[
        "_path", "_url", "_channel", "_name", "_host", "_port", "_region", "_endpoint", "_dir",
    ];
    if NON_SECRET_SUFFIXES.iter().any(|s| lc.ends_with(s)) {
        return false;
    }
    true
}

fn read_env_file(path: &Path) -> Result<Vec<(String, String)>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("read {}", path.display()))?;
    let mut out = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            let v = v.trim();
            let v = v.strip_prefix('"').and_then(|s| s.strip_suffix('"')).unwrap_or(v);
            let v = v.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')).unwrap_or(v);
            out.push((k.trim().to_string(), v.to_string()));
        }
    }
    Ok(out)
}

fn parse_kv_pairs(pairs: &[String]) -> Result<Vec<(String, String)>> {
    pairs
        .iter()
        .map(|p| {
            p.split_once('=')
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .ok_or_else(|| anyhow!("invalid KEY=VALUE: {}", p))
        })
        .collect()
}

fn parse_tags(raw: &[String]) -> Result<Vec<(String, String)>> {
    raw.iter()
        .map(|s| {
            s.split_once('=')
                .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
                .ok_or_else(|| anyhow!("invalid tag (need KEY=VALUE): {}", s))
        })
        .collect()
}

fn hash8(value: &str) -> String {
    let mut h = Sha256::new();
    h.update(value.as_bytes());
    format!("{:x}", h.finalize())[..8].to_string()
}

async fn get_parameters_by_path(client: &Client, prefix: &str) -> Result<Vec<Parameter>> {
    let mut all = Vec::new();
    let mut next: Option<String> = None;
    loop {
        let mut req = client
            .get_parameters_by_path()
            .path(prefix)
            .recursive(true)
            .with_decryption(true);
        if let Some(t) = &next {
            req = req.next_token(t);
        }
        let res = req.send().await.with_context(|| format!("get params {}", prefix))?;
        if let Some(ps) = res.parameters {
            all.extend(ps);
        }
        match res.next_token {
            Some(t) => next = Some(t),
            None => break,
        }
    }
    Ok(all)
}

/// タグで絞り込んだ parameter の名前集合を返す（DescribeParameters は値を返さない）
async fn names_filtered_by_tags(
    client: &Client,
    tag_filters: &[(String, String)],
) -> Result<Vec<String>> {
    let filters: Vec<ParameterStringFilter> = tag_filters
        .iter()
        .map(|(k, v)| {
            ParameterStringFilter::builder()
                .key(format!("tag:{}", k))
                .option("Equals")
                .values(v.clone())
                .build()
                .map_err(|e| anyhow!("build tag filter: {}", e))
        })
        .collect::<Result<_>>()?;

    let mut names = Vec::new();
    let mut next: Option<String> = None;
    loop {
        let mut req = client.describe_parameters().set_parameter_filters(Some(filters.clone()));
        if let Some(t) = &next {
            req = req.next_token(t);
        }
        let res = req.send().await.context("describe_parameters with tag filter")?;
        if let Some(ps) = res.parameters {
            names.extend(ps.into_iter().filter_map(|p| p.name));
        }
        match res.next_token {
            Some(t) => next = Some(t),
            None => break,
        }
    }
    Ok(names)
}

/// 名前集合から値付き Parameter を取る (GetParameters は 10件/呼)
async fn get_parameters_by_names(client: &Client, names: &[String]) -> Result<Vec<Parameter>> {
    let mut out = Vec::new();
    for chunk in names.chunks(10) {
        let res = client
            .get_parameters()
            .set_names(Some(chunk.to_vec()))
            .with_decryption(true)
            .send()
            .await
            .context("get_parameters")?;
        if let Some(ps) = res.parameters {
            out.extend(ps);
        }
    }
    Ok(out)
}

fn confirm_prompt(msg: &str) -> Result<bool> {
    print!("{} [y/N]: ", msg);
    io::stdout().flush()?;
    let mut buf = String::new();
    io::stdin().read_line(&mut buf)?;
    Ok(matches!(buf.trim(), "y" | "Y" | "yes" | "YES"))
}

// ---------- commands ----------

async fn cmd_list(
    client: &Client,
    app: Option<String>,
    all: bool,
    keys_only: bool,
    raw_tags: Vec<String>,
) -> Result<()> {
    let prefix = if all {
        PREFIX_ROOT.to_string()
    } else {
        let a = match app {
            Some(a) => a,
            None => detect_app_from_cwd()?,
        };
        app_prefix(&a)
    };

    let tag_filters = parse_tags(&raw_tags)?;

    // tag フィルタがあれば DescribeParameters → prefix 絞り込み → GetParameters
    // なければ普通に GetParametersByPath
    let params: Vec<Parameter> = if tag_filters.is_empty() {
        get_parameters_by_path(client, &prefix).await?
    } else {
        let names = names_filtered_by_tags(client, &tag_filters).await?;
        let prefix_slash = format!("{}/", prefix.trim_end_matches('/'));
        let filtered: Vec<String> = names
            .into_iter()
            .filter(|n| n == &prefix || n.starts_with(&prefix_slash))
            .collect();
        if filtered.is_empty() {
            println!("(no parameters match tag filter under {})", prefix.dimmed());
            return Ok(());
        }
        get_parameters_by_names(client, &filtered).await?
    };

    if params.is_empty() {
        println!("(no parameters under {})", prefix.dimmed());
        return Ok(());
    }

    if all {
        let mut by_app: BTreeMap<String, Vec<(String, String, bool)>> = BTreeMap::new();
        for p in &params {
            let name = p.name().unwrap_or_default();
            let rest = name.strip_prefix(&format!("{}/", PREFIX_ROOT)).unwrap_or(name);
            let (app_name, tail) = rest.split_once('/').unwrap_or((rest, ""));
            let env_key = tail.replace(['/', '-'], "_").to_uppercase();
            let value = p.value().unwrap_or_default().to_string();
            let secure = matches!(p.r#type(), Some(&ParameterType::SecureString));
            by_app.entry(app_name.to_string()).or_default().push((env_key, value, secure));
        }
        for (app_name, mut entries) in by_app {
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            println!("{}", format!("[{}]", app_name).bold().cyan());
            for (k, v, secure) in entries {
                let label = if secure { "🔒" } else { "  " };
                if keys_only {
                    println!("  {} {}", label, k);
                } else {
                    println!("  {} {}={}", label, k, v);
                }
            }
        }
    } else {
        let mut entries: Vec<(String, String, bool)> = params
            .iter()
            .map(|p| {
                let name = p.name().unwrap_or_default();
                let key = ssm_name_to_env_key(name, &prefix);
                let value = p.value().unwrap_or_default().to_string();
                let secure = matches!(p.r#type(), Some(&ParameterType::SecureString));
                (key, value, secure)
            })
            .collect();
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        println!("{}", format!("# {} ({} variables)", prefix, entries.len()).dimmed());
        for (k, v, secure) in entries {
            let label = if secure { "🔒" } else { "  " };
            if keys_only {
                println!("{} {}", label, k);
            } else {
                println!("{} {}={}", label, k, v);
            }
        }
    }
    Ok(())
}

async fn cmd_put(
    client: &Client,
    pairs: Vec<String>,
    env: Option<PathBuf>,
    app: Option<String>,
    plain: bool,
    raw_tags: Vec<String>,
) -> Result<()> {
    let app = match app {
        Some(a) => a,
        None => detect_app_from_cwd()?,
    };
    let prefix = app_prefix(&app);

    let kvs: Vec<(String, String)> = if let Some(path) = env {
        read_env_file(&path)?
    } else if !pairs.is_empty() {
        parse_kv_pairs(&pairs)?
    } else {
        bail!("either --env <file> or KEY=VALUE arguments are required");
    };

    if kvs.is_empty() {
        bail!("no key=value to put");
    }

    let extra_tags = parse_tags(&raw_tags)?;

    // tag の衝突チェック: app を user 指定で上書きできないようにする
    if extra_tags.iter().any(|(k, _)| k == "app") {
        bail!("`app` tag is reserved; do not pass --tag app=...");
    }

    for (k, v) in &kvs {
        let name = format!("{}/{}", prefix, env_key_to_ssm_tail(k));
        let ptype = if plain || !should_be_secure(k) {
            ParameterType::String
        } else {
            ParameterType::SecureString
        };

        client
            .put_parameter()
            .name(&name)
            .value(v)
            .r#type(ptype.clone())
            .overwrite(true)
            .send()
            .await
            .with_context(|| format!("put-parameter {}", name))?;

        // tag: app + 任意タグ
        let mut tag_objs: Vec<Tag> = Vec::with_capacity(1 + extra_tags.len());
        tag_objs.push(
            Tag::builder()
                .key("app")
                .value(&app)
                .build()
                .map_err(|e| anyhow!("build app tag: {}", e))?,
        );
        for (tk, tv) in &extra_tags {
            tag_objs.push(
                Tag::builder()
                    .key(tk)
                    .value(tv)
                    .build()
                    .map_err(|e| anyhow!("build tag {}={}: {}", tk, tv, e))?,
            );
        }
        let _ = client
            .add_tags_to_resource()
            .resource_type(ResourceTypeForTagging::Parameter)
            .resource_id(&name)
            .set_tags(Some(tag_objs))
            .send()
            .await;

        let type_label = match ptype {
            ParameterType::SecureString => "SecureString".yellow(),
            _ => "String".green(),
        };
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
        println!("  ✓ {} ({}, len={}){}", name, type_label, v.len(), tag_note);
    }
    Ok(())
}

async fn cmd_delete(
    client: &Client,
    target: String,
    app: Option<String>,
    yes: bool,
    recursive: bool,
) -> Result<()> {
    let absolute = if target.starts_with('/') {
        target.clone()
    } else {
        let a = match app {
            Some(a) => a,
            None => detect_app_from_cwd()?,
        };
        format!("{}/{}", app_prefix(&a), env_key_to_ssm_tail(&target))
    };

    if recursive {
        let params = get_parameters_by_path(client, &absolute).await?;
        if params.is_empty() {
            println!("(no parameters under {})", absolute);
            return Ok(());
        }
        println!("about to delete {} parameters under {}:", params.len(), absolute.bold());
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
        for chunk in names.chunks(10) {
            let res = client
                .delete_parameters()
                .set_names(Some(chunk.to_vec()))
                .send()
                .await?;
            for n in res.deleted_parameters.unwrap_or_default() {
                println!("  ✓ deleted {}", n);
            }
            for n in res.invalid_parameters.unwrap_or_default() {
                println!("  ✗ invalid {}", n);
            }
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

async fn cmd_show(client: &Client, key: String, app: Option<String>) -> Result<()> {
    let name = if key.starts_with('/') {
        key.clone()
    } else {
        let a = match app {
            Some(a) => a,
            None => detect_app_from_cwd()?,
        };
        format!("{}/{}", app_prefix(&a), env_key_to_ssm_tail(&key))
    };
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
        let label = if secure { "SecureString".yellow() } else { "String".green() };
        println!("# {} ({})", name.dimmed(), label);
        println!("{}", value);
    }
    Ok(())
}

async fn cmd_dirs(client: &Client) -> Result<()> {
    let params = get_parameters_by_path(client, PREFIX_ROOT).await?;
    let mut by_app: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    for p in &params {
        let name = p.name().unwrap_or_default();
        let rest = name.strip_prefix(&format!("{}/", PREFIX_ROOT)).unwrap_or(name);
        let app = rest.split('/').next().unwrap_or(rest).to_string();
        let entry = by_app.entry(app).or_insert((0, 0));
        entry.0 += 1;
        if matches!(p.r#type(), Some(&ParameterType::SecureString)) {
            entry.1 += 1;
        }
    }
    if by_app.is_empty() {
        println!("(no parameters under {})", PREFIX_ROOT);
        return Ok(());
    }
    println!("{:<32} {:>6} {:>8}", "app".bold(), "total".bold(), "secure".bold());
    for (app, (total, secure)) in by_app {
        println!("{:<32} {:>6} {:>8}", app, total, secure);
    }
    Ok(())
}

async fn cmd_sync(client: &Client, app: Option<String>, out: PathBuf) -> Result<()> {
    let app = match app {
        Some(a) => a,
        None => detect_app_from_cwd()?,
    };
    let prefix = app_prefix(&app);
    let params = get_parameters_by_path(client, &prefix).await?;
    if params.is_empty() {
        bail!("no parameters under {}", prefix);
    }

    let mut entries: Vec<(String, String)> = params
        .iter()
        .map(|p| {
            let name = p.name().unwrap_or_default();
            let key = ssm_name_to_env_key(name, &prefix);
            let value = p.value().unwrap_or_default().to_string();
            (key, value)
        })
        .collect();
    entries.sort_by(|a, b| a.0.cmp(&b.0));

    let body: String = entries.iter().map(|(k, v)| format!("{}={}\n", k, v)).collect();

    let existing = std::fs::read_to_string(&out).ok();
    if existing.as_deref() == Some(body.as_str()) {
        println!("ssmm: no change ({} variables)", entries.len());
        return Ok(());
    }

    let tmp = out.with_extension("env.tmp");
    std::fs::write(&tmp, &body).with_context(|| format!("write {}", tmp.display()))?;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    std::fs::rename(&tmp, &out)?;
    println!(
        "ssmm: wrote {} variables to {}",
        entries.len(),
        out.display()
    );
    Ok(())
}

async fn cmd_migrate(
    client: &Client,
    old_prefix: String,
    new_prefix: String,
    delete_old: bool,
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

    let mut migrated_names: Vec<String> = Vec::new();
    for p in &params {
        let old_name = p.name().unwrap_or_default().to_string();
        let suffix = old_name
            .strip_prefix(&format!("{}/", old_prefix.trim_end_matches('/')))
            .unwrap_or(&old_name);
        let new_name = format!("{}/{}", new_prefix.trim_end_matches('/'), suffix);
        let value = p.value().unwrap_or_default();
        let ptype = p.r#type().cloned().unwrap_or(ParameterType::String);

        client
            .put_parameter()
            .name(&new_name)
            .value(value)
            .r#type(ptype.clone())
            .overwrite(true)
            .send()
            .await
            .with_context(|| format!("put {}", new_name))?;

        if let Some(new_app) = new_prefix
            .strip_prefix(&format!("{}/", PREFIX_ROOT))
            .map(|s| s.split('/').next().unwrap_or(s).to_string())
        {
            let tag = Tag::builder()
                .key("app")
                .value(&new_app)
                .build()
                .map_err(|e| anyhow!("build tag: {}", e))?;
            let _ = client
                .add_tags_to_resource()
                .resource_type(ResourceTypeForTagging::Parameter)
                .resource_id(&new_name)
                .tags(tag)
                .send()
                .await;
        }

        println!("  ✓ {} → {}", old_name, new_name);
        migrated_names.push(old_name);
    }

    if delete_old {
        println!("deleting {} old parameters...", migrated_names.len());
        for chunk in migrated_names.chunks(10) {
            let res = client
                .delete_parameters()
                .set_names(Some(chunk.to_vec()))
                .send()
                .await?;
            for n in res.deleted_parameters.unwrap_or_default() {
                println!("  ✓ deleted {}", n);
            }
        }
    } else {
        println!(
            "{} old parameters preserved. Re-run with --delete-old to remove.",
            migrated_names.len()
        );
    }
    Ok(())
}

async fn cmd_check(
    client: &Client,
    duplicates: bool,
    values: bool,
    show_values: bool,
) -> Result<()> {
    if !duplicates && !values {
        println!("(nothing to check; pass --duplicates and/or --values)");
        return Ok(());
    }

    let params = get_parameters_by_path(client, PREFIX_ROOT).await?;
    if params.is_empty() {
        println!("(no parameters under {})", PREFIX_ROOT);
        return Ok(());
    }

    if duplicates {
        let mut by_tail: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for p in &params {
            let name = p.name().unwrap_or_default();
            let rest = name.strip_prefix(&format!("{}/", PREFIX_ROOT)).unwrap_or(name);
            let (app, tail) = rest.split_once('/').unwrap_or((rest, ""));
            by_tail.entry(tail.to_string()).or_default().push(app.to_string());
        }
        println!("{}", "[key-name duplicates]".bold());
        let mut found = false;
        for (tail, apps) in &by_tail {
            if apps.len() >= 2 {
                found = true;
                println!(
                    "  {}: {} [{} apps]",
                    tail.yellow().bold(),
                    apps.join(", "),
                    apps.len()
                );
            }
        }
        if !found {
            println!("  no duplicates.");
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
        let mut found = false;
        let groups: Vec<_> = by_value
            .iter()
            .filter(|(_, names)| names.len() >= 2)
            .collect();
        for (value, names) in groups {
            found = true;
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
        if !found {
            println!("  no value duplicates.");
        }
    }

    Ok(())
}
