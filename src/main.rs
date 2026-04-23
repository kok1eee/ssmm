use anyhow::{Context, Result, anyhow, bail};
use aws_sdk_ssm::Client;
use aws_sdk_ssm::types::{
    Parameter, ParameterStringFilter, ParameterType, ResourceTypeForTagging, Tag,
};
use clap::{ArgAction, Parser, Subcommand};
use colored::Colorize;
use futures::stream::{self, StreamExt, TryStreamExt};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use std::io::{self, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

const DEFAULT_PREFIX_ROOT: &str = "/amu-revo";
const DEFAULT_SHARED_PREFIX: &str = "/amu-revo/shared";
const SSMM_ENV_VAR: &str = "SSMM_PREFIX_ROOT";

/// SSM PutParameter の TPS (~3) に合わせたデフォルト書き込み並列度。
/// `--write-concurrency N` で上書き可。read 系はより高くても安全。
const DEFAULT_WRITE_CONCURRENCY: usize = 3;
const DEFAULT_READ_CONCURRENCY: usize = 10;

static PREFIX_ROOT: OnceLock<String> = OnceLock::new();
static SHARED_PREFIX: OnceLock<String> = OnceLock::new();
static WRITE_CONCURRENCY: OnceLock<usize> = OnceLock::new();
static READ_CONCURRENCY: OnceLock<usize> = OnceLock::new();

fn prefix_root() -> &'static str {
    PREFIX_ROOT
        .get()
        .map(String::as_str)
        .unwrap_or(DEFAULT_PREFIX_ROOT)
}

fn shared_prefix() -> &'static str {
    SHARED_PREFIX
        .get()
        .map(String::as_str)
        .unwrap_or(DEFAULT_SHARED_PREFIX)
}

fn write_concurrency() -> usize {
    WRITE_CONCURRENCY
        .get()
        .copied()
        .unwrap_or(DEFAULT_WRITE_CONCURRENCY)
}

fn read_concurrency() -> usize {
    READ_CONCURRENCY
        .get()
        .copied()
        .unwrap_or(DEFAULT_READ_CONCURRENCY)
}

async fn run_bounded<F, Fut, T>(futs: F, limit: usize) -> Result<Vec<T>>
where
    F: IntoIterator<Item = Fut>,
    Fut: std::future::Future<Output = Result<T>>,
{
    stream::iter(futs)
        .buffer_unordered(limit)
        .try_collect()
        .await
}

#[derive(Parser)]
#[command(
    name = "ssmm",
    version,
    about = "AWS SSM Parameter Store helper for team-scoped .env sync"
)]
struct Cli {
    /// Root prefix all parameters live under
    /// (default: /amu-revo; override via $SSMM_PREFIX_ROOT env var)
    #[arg(long, global = true)]
    prefix: Option<String>,

    /// Max concurrent SSM writes (PutParameter / DeleteParameters /
    /// AddTagsToResource). Default: 3 (matches standard-parameter TPS).
    #[arg(long, global = true, value_name = "N")]
    write_concurrency: Option<usize>,

    /// Max concurrent SSM reads (GetParameters / DescribeParameters).
    /// Default: 10.
    #[arg(long, global = true, value_name = "N")]
    read_concurrency: Option<usize>,

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
        /// Force ALL values to String (ignores per-key overrides and heuristic)
        #[arg(long)]
        plain_all: bool,
        /// Force specific keys to String (repeatable: --plain-key LOG_DIR --plain-key DB_HOST)
        #[arg(long = "plain-key", action = ArgAction::Append, value_name = "KEY")]
        plain_keys: Vec<String>,
        /// Force specific keys to SecureString (repeatable: --secure DATABASE_URL)
        #[arg(long = "secure", action = ArgAction::Append, value_name = "KEY")]
        secure_keys: Vec<String>,
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
    /// Sync SSM -> .env (app + /amu-revo/shared/* + tagged overlays)
    Sync {
        #[arg(long)]
        app: Option<String>,
        #[arg(long, short, default_value = "./.env")]
        out: PathBuf,
        /// Skip /amu-revo/shared/* overlay (default: included)
        #[arg(long)]
        no_shared: bool,
        /// Also include parameters matching tag (repeatable)
        #[arg(long = "include-tag", action = ArgAction::Append, value_name = "KEY=VALUE")]
        include_tags: Vec<String>,
        /// Exit with non-zero status when any shared / tag key is overridden
        /// by an app-level key (instead of just warning to stderr)
        #[arg(long)]
        strict: bool,
    },
    /// Migrate parameters from an old prefix to a new prefix
    Migrate {
        old_prefix: String,
        new_prefix: String,
        /// Delete source parameters after copy. Requires --confirm to actually
        /// delete; without --confirm the command only dumps a backup and
        /// reports what WOULD be deleted (safe default).
        #[arg(long)]
        delete_old: bool,
        /// Actually perform the delete step of --delete-old. A JSON backup is
        /// written to /tmp/ssmm-migrate-backup-<timestamp>.json in either case.
        #[arg(long)]
        confirm: bool,
    },
    /// Check for duplicate keys or identical values across apps
    Check {
        #[arg(long)]
        duplicates: bool,
        #[arg(long)]
        values: bool,
        /// Reveal actual values in --values output (default: SHA-256 prefix only)
        #[arg(long)]
        show_values: bool,
    },
    /// Manage tags on existing parameters
    Tag {
        #[command(subcommand)]
        action: TagAction,
    },
}

#[derive(Subcommand)]
enum TagAction {
    Add {
        key: String,
        #[arg(value_name = "KEY=VALUE", required = true)]
        tags: Vec<String>,
        #[arg(long)]
        app: Option<String>,
    },
    Remove {
        key: String,
        #[arg(value_name = "TAG_KEY", required = true)]
        tag_keys: Vec<String>,
        #[arg(long)]
        app: Option<String>,
    },
    List {
        key: String,
        #[arg(long)]
        app: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    // stdout パイプ先が閉じても panic ではなく静かに終了させる (例: `ssmm list | head`)
    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }

    let cli = Cli::parse();

    let root = cli
        .prefix
        .clone()
        .or_else(|| std::env::var(SSMM_ENV_VAR).ok())
        .unwrap_or_else(|| DEFAULT_PREFIX_ROOT.to_string());
    let root = root.trim_end_matches('/').to_string();
    if !root.starts_with('/') {
        bail!("prefix must start with '/': got {:?}", root);
    }
    let shared = format!("{}/shared", root);
    PREFIX_ROOT
        .set(root)
        .expect("PREFIX_ROOT should only be set once during startup");
    SHARED_PREFIX
        .set(shared)
        .expect("SHARED_PREFIX should only be set once during startup");
    if let Some(n) = cli.write_concurrency {
        if n == 0 {
            bail!("--write-concurrency must be >= 1");
        }
        WRITE_CONCURRENCY.set(n).ok();
    }
    if let Some(n) = cli.read_concurrency {
        if n == 0 {
            bail!("--read-concurrency must be >= 1");
        }
        READ_CONCURRENCY.set(n).ok();
    }

    let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .retry_config(aws_config::retry::RetryConfig::adaptive().with_max_attempts(10))
        .load()
        .await;
    let client = Client::new(&config);

    match cli.command {
        Command::List {
            app,
            all,
            keys_only,
            tags,
        } => cmd_list(&client, app, all, keys_only, tags).await,
        Command::Put {
            pairs,
            env,
            app,
            plain_all,
            plain_keys,
            secure_keys,
            tags,
        } => {
            cmd_put(
                &client,
                pairs,
                env,
                app,
                plain_all,
                plain_keys,
                secure_keys,
                tags,
            )
            .await
        }
        Command::Delete {
            target,
            app,
            yes,
            recursive,
        } => cmd_delete(&client, target, app, yes, recursive).await,
        Command::Show { key, app } => cmd_show(&client, key, app).await,
        Command::Dirs => cmd_dirs(&client).await,
        Command::Sync {
            app,
            out,
            no_shared,
            include_tags,
            strict,
        } => cmd_sync(&client, app, out, no_shared, include_tags, strict).await,
        Command::Migrate {
            old_prefix,
            new_prefix,
            delete_old,
            confirm,
        } => cmd_migrate(&client, old_prefix, new_prefix, delete_old, confirm).await,
        Command::Check {
            duplicates,
            values,
            show_values,
        } => cmd_check(&client, duplicates, values, show_values).await,
        Command::Tag { action } => cmd_tag(&client, action).await,
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
    Ok(name.replace('_', "-"))
}

fn resolve_app(app: Option<String>) -> Result<String> {
    match app {
        Some(a) => Ok(a),
        None => detect_app_from_cwd(),
    }
}

fn app_prefix(app: &str) -> String {
    format!("{}/{}", prefix_root(), app)
}

fn resolve_param_name(key: &str, app: Option<String>) -> Result<String> {
    if key.starts_with('/') {
        return Ok(key.to_string());
    }
    Ok(format!(
        "{}/{}",
        app_prefix(&resolve_app(app)?),
        env_key_to_ssm_tail(key)
    ))
}

fn ssm_name_to_env_key(name: &str, prefix: &str) -> String {
    let trimmed_prefix = format!("{}/", prefix.trim_end_matches('/'));
    let rest = name.strip_prefix(&trimmed_prefix).unwrap_or(name);
    rest.replace(['/', '-'], "_").to_uppercase()
}

/// /amu-revo/<app>/<tail...> → <TAIL_UPCASE_UNDERSCORED>   (app セグメントを落とす)
fn ssm_name_to_env_key_from_root(name: &str) -> String {
    let rest = name
        .strip_prefix(&format!("{}/", prefix_root()))
        .unwrap_or(name);
    let after_app = rest.split_once('/').map(|(_, tail)| tail).unwrap_or("");
    after_app.replace(['/', '-'], "_").to_uppercase()
}

fn env_key_to_ssm_tail(key: &str) -> String {
    key.to_lowercase().replace('_', "-")
}

/// Heuristic: default to SecureString (conservative). Flip to String only for
/// suffixes that strongly imply structural/public config (paths, hostnames,
/// ports, region strings, Slack channel IDs, etc.).
///
/// `_url` is intentionally NOT in the safe list — URLs commonly embed
/// credentials (e.g. `postgres://user:pass@host/db`, Slack webhook URLs,
/// Sentry DSNs). Leaking them as plaintext SSM parameters is the #1
/// real-world foot-gun. Users who want plaintext storage can pass
/// `--plain KEY` explicitly.
fn should_be_secure(key: &str) -> bool {
    let lc = key.to_lowercase();
    const NON_SECRET_SUFFIXES: &[&str] = &[
        "_path",
        "_dir",
        "_channel",
        "_name",
        "_host",
        "_port",
        "_region",
        "_endpoint",
    ];
    !NON_SECRET_SUFFIXES.iter().any(|s| lc.ends_with(s))
}

fn build_tag(k: &str, v: &str) -> Result<Tag> {
    Tag::builder()
        .key(k)
        .value(v)
        .build()
        .map_err(|e| anyhow!("build tag {}={}: {}", k, v, e))
}

fn build_tags(pairs: &[(String, String)]) -> Result<Vec<Tag>> {
    pairs.iter().map(|(k, v)| build_tag(k, v)).collect()
}

fn read_env_file(path: &Path) -> Result<Vec<(String, String)>> {
    let content =
        std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let mut out = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            let v = v.trim();
            let v = v
                .strip_prefix('"')
                .and_then(|s| s.strip_suffix('"'))
                .unwrap_or(v);
            let v = v
                .strip_prefix('\'')
                .and_then(|s| s.strip_suffix('\''))
                .unwrap_or(v);
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
        let res = req
            .send()
            .await
            .with_context(|| format!("get params {}", prefix))?;
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

/// タグフィルタで parameter name を取得。path_prefix を渡すと SSM 側で prefix 絞り込み
/// (Path + Recursive) を併用し、クライアント側の post-filter を不要にする。
async fn names_filtered_by_tags(
    client: &Client,
    tag_filters: &[(String, String)],
    path_prefix: Option<&str>,
) -> Result<Vec<String>> {
    let mut filters: Vec<ParameterStringFilter> = Vec::with_capacity(tag_filters.len() + 1);
    if let Some(p) = path_prefix {
        filters.push(
            ParameterStringFilter::builder()
                .key("Path")
                .option("Recursive")
                .values(p)
                .build()
                .map_err(|e| anyhow!("build Path filter: {}", e))?,
        );
    }
    for (k, v) in tag_filters {
        filters.push(
            ParameterStringFilter::builder()
                .key(format!("tag:{}", k))
                .option("Equals")
                .values(v.clone())
                .build()
                .map_err(|e| anyhow!("build tag filter: {}", e))?,
        );
    }

    let mut names = Vec::new();
    let mut next: Option<String> = None;
    loop {
        let mut req = client
            .describe_parameters()
            .set_parameter_filters(Some(filters.clone()));
        if let Some(t) = &next {
            req = req.next_token(t);
        }
        let res = req
            .send()
            .await
            .context("describe_parameters with filters")?;
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

async fn get_parameters_by_names(client: &Client, names: &[String]) -> Result<Vec<Parameter>> {
    if names.is_empty() {
        return Ok(Vec::new());
    }
    let futs = names.chunks(10).map(|chunk| {
        let chunk = chunk.to_vec();
        async move {
            client
                .get_parameters()
                .set_names(Some(chunk))
                .with_decryption(true)
                .send()
                .await
                .context("get_parameters")
        }
    });
    let results = run_bounded(futs, read_concurrency()).await?;
    Ok(results
        .into_iter()
        .flat_map(|r| r.parameters.unwrap_or_default())
        .collect())
}

async fn delete_parameters_batched(client: &Client, names: &[String]) -> Result<Vec<String>> {
    if names.is_empty() {
        return Ok(Vec::new());
    }
    let futs = names.chunks(10).map(|chunk| {
        let chunk = chunk.to_vec();
        async move {
            client
                .delete_parameters()
                .set_names(Some(chunk))
                .send()
                .await
                .context("delete_parameters")
        }
    });
    let results = run_bounded(futs, write_concurrency()).await?;
    Ok(results
        .into_iter()
        .flat_map(|r| r.deleted_parameters.unwrap_or_default())
        .collect())
}

fn confirm_prompt(msg: &str) -> Result<bool> {
    print!("{} [y/N]: ", msg);
    io::stdout().flush()?;
    let mut buf = String::new();
    io::stdin().read_line(&mut buf)?;
    Ok(matches!(buf.trim(), "y" | "Y" | "yes" | "YES"))
}

// ---------- commands ----------

fn print_entry(key: &str, value: Option<&str>, secure: bool, keys_only: bool, indent: &str) {
    let label = if secure { "🔒" } else { "  " };
    if keys_only {
        println!("{}{} {}", indent, label, key);
    } else {
        println!("{}{} {}={}", indent, label, key, value.unwrap_or(""));
    }
}

async fn cmd_list(
    client: &Client,
    app: Option<String>,
    all: bool,
    keys_only: bool,
    raw_tags: Vec<String>,
) -> Result<()> {
    let prefix = if all {
        prefix_root().to_string()
    } else {
        app_prefix(&resolve_app(app)?)
    };

    let tag_filters = parse_tags(&raw_tags)?;

    let params: Vec<Parameter> = if tag_filters.is_empty() {
        get_parameters_by_path(client, &prefix).await?
    } else {
        let names = names_filtered_by_tags(client, &tag_filters, Some(&prefix)).await?;
        if names.is_empty() {
            println!("(no parameters match tag filter under {})", prefix.dimmed());
            return Ok(());
        }
        get_parameters_by_names(client, &names).await?
    };

    if params.is_empty() {
        println!("(no parameters under {})", prefix.dimmed());
        return Ok(());
    }

    if all {
        let prefix_slash = format!("{}/", prefix_root());
        let mut by_app: BTreeMap<String, Vec<(String, String, bool)>> = BTreeMap::new();
        for p in &params {
            let name = p.name().unwrap_or_default();
            let rest = name.strip_prefix(&prefix_slash).unwrap_or(name);
            let (app_name, _) = rest.split_once('/').unwrap_or((rest, ""));
            let key = ssm_name_to_env_key_from_root(name);
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
    } else {
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
    }
    Ok(())
}

/// put 時の型判定の根拠を出力用に記録する
#[derive(Clone, Copy)]
enum TypeReason {
    ForcedPlainAll,
    ForcedPlainKey,
    ForcedSecureKey,
    AutoSuffix,
    AutoDefault,
}

impl TypeReason {
    fn label(self) -> &'static str {
        match self {
            TypeReason::ForcedPlainAll => "forced: --plain-all",
            TypeReason::ForcedPlainKey => "forced: --plain-key",
            TypeReason::ForcedSecureKey => "forced: --secure",
            TypeReason::AutoSuffix => "auto: suffix",
            TypeReason::AutoDefault => "auto: default",
        }
    }
}

fn resolve_type(
    key: &str,
    plain_all: bool,
    plain_keys: &HashSet<String>,
    secure_keys: &HashSet<String>,
) -> (ParameterType, TypeReason) {
    if plain_all {
        return (ParameterType::String, TypeReason::ForcedPlainAll);
    }
    if secure_keys.contains(key) {
        return (ParameterType::SecureString, TypeReason::ForcedSecureKey);
    }
    if plain_keys.contains(key) {
        return (ParameterType::String, TypeReason::ForcedPlainKey);
    }
    if should_be_secure(key) {
        (ParameterType::SecureString, TypeReason::AutoDefault)
    } else {
        (ParameterType::String, TypeReason::AutoSuffix)
    }
}

#[allow(clippy::too_many_arguments)]
async fn cmd_put(
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
    let prefix = app_prefix(&app);

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

    let app_tag_pair = vec![("app".to_string(), app.clone())];
    let all_tags: Vec<(String, String)> = app_tag_pair
        .into_iter()
        .chain(extra_tags.iter().cloned())
        .collect();

    let futs = kvs.iter().map(|(k, v)| {
        let name = format!("{}/{}", prefix, env_key_to_ssm_tail(k));
        let (ptype, reason) = resolve_type(k, plain_all, &plain_set, &secure_set);
        let tags = all_tags.clone();
        let key = k.clone();
        let value = v.clone();
        async move {
            let tag_objs = build_tags(&tags)?;
            client
                .put_parameter()
                .name(&name)
                .value(&value)
                .r#type(ptype.clone())
                .overwrite(true)
                .send()
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

async fn cmd_show(client: &Client, key: String, app: Option<String>) -> Result<()> {
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

async fn cmd_dirs(client: &Client) -> Result<()> {
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

async fn cmd_sync(
    client: &Client,
    app: Option<String>,
    out: PathBuf,
    no_shared: bool,
    raw_include_tags: Vec<String>,
    strict: bool,
) -> Result<()> {
    let app = resolve_app(app)?;
    let prefix = app_prefix(&app);
    let include_tags = parse_tags(&raw_include_tags)?;
    let want_shared = !no_shared && app != "shared";

    // 3 本の SSM 問い合わせを並列化 (hot path)
    let (app_params, shared_params, tag_names) = tokio::try_join!(
        get_parameters_by_path(client, &prefix),
        async {
            if want_shared {
                get_parameters_by_path(client, shared_prefix()).await
            } else {
                Ok(Vec::new())
            }
        },
        async {
            if include_tags.is_empty() {
                Ok(Vec::new())
            } else {
                names_filtered_by_tags(client, &include_tags, Some(prefix_root())).await
            }
        }
    )?;

    // tag_names から app/shared と重複する name を除いた残りを取得
    let already: HashSet<&str> = app_params
        .iter()
        .chain(shared_params.iter())
        .filter_map(|p| p.name())
        .collect();
    let tag_param_names: Vec<String> = tag_names
        .into_iter()
        .filter(|n| !already.contains(n.as_str()))
        .collect();
    let tag_params = get_parameters_by_names(client, &tag_param_names).await?;

    if app_params.is_empty() && shared_params.is_empty() && tag_params.is_empty() {
        bail!(
            "no parameters for sync (prefix={}, shared={}, include-tags={:?})",
            prefix,
            want_shared,
            raw_include_tags
        );
    }

    // 優先度: app > include-tag > shared
    // 同じ env key を後から上書き → app が最後に入るよう shared → tag → app の順で ingest
    let mut merged: BTreeMap<String, String> = BTreeMap::new();
    let mut shared_keys: HashSet<String> = HashSet::new();
    let mut app_keys: HashSet<String> = HashSet::new();

    for p in &shared_params {
        let key = ssm_name_to_env_key(p.name().unwrap_or_default(), shared_prefix());
        let value = p.value().unwrap_or_default().to_string();
        shared_keys.insert(key.clone());
        merged.insert(key, value);
    }
    for p in &tag_params {
        let key = ssm_name_to_env_key_from_root(p.name().unwrap_or_default());
        let value = p.value().unwrap_or_default().to_string();
        merged.insert(key, value);
    }
    for p in &app_params {
        let key = ssm_name_to_env_key(p.name().unwrap_or_default(), &prefix);
        let value = p.value().unwrap_or_default().to_string();
        app_keys.insert(key.clone());
        merged.insert(key, value);
    }

    let conflicts: Vec<&String> = app_keys.intersection(&shared_keys).collect();
    if !conflicts.is_empty() {
        let mut names: Vec<&str> = conflicts.iter().map(|s| s.as_str()).collect();
        names.sort();
        let label = if strict {
            "error:".red().bold()
        } else {
            "warning:".yellow().bold()
        };
        eprintln!(
            "{} {} shared key(s) overridden by app: {}",
            label,
            names.len(),
            names.join(", ")
        );
        if strict {
            bail!(
                "sync aborted by --strict due to {} conflict(s)",
                names.len()
            );
        }
    }

    let body: String = merged
        .iter()
        .map(|(k, v)| format!("{}={}\n", k, v))
        .collect();

    let existing = std::fs::read_to_string(&out).ok();
    if existing.as_deref() == Some(body.as_str()) {
        println!(
            "ssmm: no change ({} variables; app={}, shared={}, tag={})",
            merged.len(),
            app_params.len(),
            shared_params.len(),
            tag_params.len()
        );
        return Ok(());
    }

    let tmp = out.with_extension("env.tmp");
    std::fs::write(&tmp, &body).with_context(|| format!("write {}", tmp.display()))?;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    std::fs::rename(&tmp, &out)?;
    println!(
        "ssmm: wrote {} variables to {} (app={}, shared={}, tag={})",
        merged.len(),
        out.display(),
        app_params.len(),
        shared_params.len(),
        tag_params.len()
    );
    Ok(())
}

async fn cmd_migrate(
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
            client
                .put_parameter()
                .name(&new_name)
                .value(&value)
                .r#type(ptype)
                .overwrite(true)
                .send()
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

async fn cmd_tag(client: &Client, action: TagAction) -> Result<()> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as IoWrite;
    use tempfile::NamedTempFile;

    #[test]
    fn ssm_name_to_env_key_basic() {
        assert_eq!(
            ssm_name_to_env_key(
                "/amu-revo/hikken-schedule/kintone-id",
                "/amu-revo/hikken-schedule"
            ),
            "KINTONE_ID"
        );
    }

    #[test]
    fn ssm_name_to_env_key_nested_segments() {
        assert_eq!(
            ssm_name_to_env_key("/amu-revo/postdata/x/kyushu/api-key", "/amu-revo/postdata"),
            "X_KYUSHU_API_KEY"
        );
    }

    #[test]
    fn ssm_name_to_env_key_from_root_strips_app() {
        assert_eq!(
            ssm_name_to_env_key_from_root("/amu-revo/app-name/kintone-id"),
            "KINTONE_ID"
        );
        assert_eq!(
            ssm_name_to_env_key_from_root("/amu-revo/postdata/x/kyushu/api-key"),
            "X_KYUSHU_API_KEY"
        );
    }

    #[test]
    fn env_key_to_ssm_tail_lowercases_and_dasheses() {
        assert_eq!(
            env_key_to_ssm_tail("KINTONE_API_TOKEN"),
            "kintone-api-token"
        );
        assert_eq!(env_key_to_ssm_tail("PTOWN_PASS"), "ptown-pass");
        assert_eq!(env_key_to_ssm_tail("A"), "a");
    }

    #[test]
    fn should_be_secure_default_true() {
        assert!(should_be_secure("KINTONE_API_TOKEN"));
        assert!(should_be_secure("SLACK_BOT_TOKEN"));
        assert!(should_be_secure("SOMETHING_UNKNOWN"));
        assert!(should_be_secure("PTOWN_USERNAME"));
    }

    #[test]
    fn should_be_secure_url_keys_are_secure() {
        // v0.1.1: `_url` suffix はもはや safe list に無い。
        // URL は credentials を含む可能性が高いため SecureString デフォルト
        assert!(should_be_secure("DATABASE_URL"));
        assert!(should_be_secure("POSTGRES_URL"));
        assert!(should_be_secure("SLACK_WEBHOOK_URL"));
        assert!(should_be_secure("GOOGLE_SPREADSHEET_URL"));
        assert!(should_be_secure("SENTRY_DSN"));
    }

    #[test]
    fn should_be_secure_public_suffixes_map_to_string() {
        assert!(!should_be_secure("GOOGLE_CREDENTIALS_PATH"));
        assert!(!should_be_secure("SLACK_CHANNEL"));
        assert!(!should_be_secure("DB_HOST"));
        assert!(!should_be_secure("HTTP_PORT"));
        assert!(!should_be_secure("AWS_REGION"));
        assert!(!should_be_secure("LOG_DIR"));
        assert!(!should_be_secure("API_ENDPOINT"));
    }

    #[test]
    fn parse_tags_basic() {
        let tags = parse_tags(&["env=prod".to_string(), "owner=backend".to_string()]).unwrap();
        assert_eq!(
            tags,
            vec![
                ("env".to_string(), "prod".to_string()),
                ("owner".to_string(), "backend".to_string()),
            ]
        );
    }

    #[test]
    fn parse_tags_trims_whitespace() {
        let tags = parse_tags(&["  env = prod  ".to_string()]).unwrap();
        assert_eq!(tags, vec![("env".to_string(), "prod".to_string())]);
    }

    #[test]
    fn parse_tags_rejects_missing_equals() {
        let err = parse_tags(&["no-equals".to_string()]).unwrap_err();
        assert!(err.to_string().contains("invalid tag"));
    }

    #[test]
    fn parse_kv_pairs_basic() {
        let pairs = parse_kv_pairs(&["A=1".to_string(), "B=2".to_string()]).unwrap();
        assert_eq!(
            pairs,
            vec![
                ("A".to_string(), "1".to_string()),
                ("B".to_string(), "2".to_string()),
            ]
        );
    }

    #[test]
    fn parse_kv_pairs_value_with_equals_sign() {
        // split_once: 最初の '=' までで分割。値内の '=' は保持
        let pairs = parse_kv_pairs(&["URL=https://a.com?x=y".to_string()]).unwrap();
        assert_eq!(
            pairs,
            vec![("URL".to_string(), "https://a.com?x=y".to_string())]
        );
    }

    #[test]
    fn hash8_is_deterministic_and_length_8() {
        assert_eq!(hash8("hello"), hash8("hello"));
        assert_ne!(hash8("hello"), hash8("world"));
        assert_eq!(hash8("hello").len(), 8);
    }

    #[test]
    fn read_env_file_handles_comments_blanks_quotes() {
        let mut f = NamedTempFile::new().unwrap();
        writeln!(f, "# this is a comment").unwrap();
        writeln!(f).unwrap();
        writeln!(f, "KEY1=value1").unwrap();
        writeln!(f, "KEY2=\"quoted\"").unwrap();
        writeln!(f, "KEY3='single'").unwrap();
        writeln!(f, "  KEY4 = trimmed  ").unwrap();
        let result = read_env_file(f.path()).unwrap();
        assert_eq!(
            result,
            vec![
                ("KEY1".to_string(), "value1".to_string()),
                ("KEY2".to_string(), "quoted".to_string()),
                ("KEY3".to_string(), "single".to_string()),
                ("KEY4".to_string(), "trimmed".to_string()),
            ]
        );
    }

    #[test]
    fn app_prefix_uses_default_prefix_root() {
        // OnceLock が未 set なら DEFAULT_PREFIX_ROOT が使われる
        assert_eq!(app_prefix("foo"), format!("{}/foo", DEFAULT_PREFIX_ROOT));
    }
}
