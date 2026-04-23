use clap::{ArgAction, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "ssmm",
    version,
    about = "AWS SSM Parameter Store helper for team-scoped .env sync"
)]
pub struct Cli {
    /// Root prefix all parameters live under (REQUIRED).
    /// Can also be set via $SSMM_PREFIX_ROOT env var. No default is provided
    /// — ssmm exits with an error if neither is configured.
    #[arg(long, global = true)]
    pub prefix: Option<String>,

    /// Max concurrent SSM writes (PutParameter / DeleteParameters /
    /// AddTagsToResource). Default: 3 (matches standard-parameter TPS).
    #[arg(long, global = true, value_name = "N")]
    pub write_concurrency: Option<usize>,

    /// Max concurrent SSM reads (GetParameters / DescribeParameters).
    /// Default: 10.
    #[arg(long, global = true, value_name = "N")]
    pub read_concurrency: Option<usize>,

    /// Use Advanced tier parameters (up to 8KB, $0.05/month per parameter).
    /// Default: Standard tier (4KB, free). Required for values exceeding 4KB
    /// (certificates, PEM keys, large JSON blobs).
    #[arg(long, global = true)]
    pub advanced: bool,

    /// Custom KMS key ID / ARN / alias for SecureString encryption.
    /// Default: `alias/aws/ssm` (AWS-managed key). Set to a team-scoped CMK
    /// (e.g. `alias/myteam-ssm`) to separate decrypt permissions per team.
    /// Only affects newly-created SecureString parameters; existing ones keep
    /// their original key.
    #[arg(long, global = true, value_name = "KEY")]
    pub kms_key_id: Option<String>,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// List parameters for an app (CWD auto-detect if no --app)
    List {
        #[arg(long)]
        app: Option<String>,
        /// Show all parameters under the configured prefix
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
    /// List all app namespaces under the configured prefix with parameter counts
    Dirs,
    /// Sync SSM -> .env (app + /<prefix>/shared/* + tagged overlays)
    Sync {
        #[arg(long)]
        app: Option<String>,
        #[arg(long, short, default_value = "./.env")]
        out: PathBuf,
        /// Skip /<prefix>/shared/* overlay (default: included)
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
    /// Generate a systemd drop-in that switches a unit from sync-mode
    /// (EnvironmentFile= .env) to exec-mode (`ssmm exec` direct injection).
    ///
    /// By default this is a dry-run: the drop-in is printed to stdout. Pass
    /// `--apply` to write the file and run `systemctl daemon-reload`. Revert
    /// by removing the drop-in file and reloading:
    ///
    ///     rm ~/.config/systemd/user/<unit>.d/exec-mode.conf && \
    ///         systemctl --user daemon-reload
    ///
    /// ssmm deliberately does NOT auto-parse the current unit's ExecStart,
    /// since systemd's show/cat output is fragile across versions and
    /// drop-in resets. Paste the command from `systemctl cat <unit>`
    /// into --exec-cmd.
    MigrateToExec {
        /// systemd unit name (e.g. `myapp.service`)
        #[arg(long, value_name = "UNIT")]
        unit: String,
        /// SSM app name to inject (dash-case tail of /<prefix>/<app>/...)
        #[arg(long)]
        app: String,
        /// Full command to exec after SSM injection. Paste the existing
        /// `ExecStart=` value from `systemctl cat <unit>` here.
        /// Example: --exec-cmd "/usr/bin/uv run python app.py --mode prod"
        #[arg(long, value_name = "CMD")]
        exec_cmd: String,
        /// Target system-wide systemd instead of --user (default: user)
        #[arg(long)]
        system: bool,
        /// EnvironmentFile= entries to keep (not SSM-derived, e.g. sdtab
        /// common env). Repeatable. Written with `-` prefix so missing files
        /// don't break startup.
        #[arg(long = "keep-env-file", action = ArgAction::Append, value_name = "PATH")]
        keep_env_files: Vec<PathBuf>,
        /// ExecStartPre= entries to set (replaces any existing ExecStartPre).
        /// Repeatable; order preserved. Omit to clear ExecStartPre entirely.
        #[arg(long = "pre-exec", action = ArgAction::Append, value_name = "CMD")]
        pre_execs: Vec<String>,
        /// Absolute path to ssmm binary used in the generated ExecStart=.
        /// Default: `$HOME/.cargo/bin/ssmm` (stable install location —
        /// do not use a `target/release/` path, which `cargo clean` removes).
        #[arg(long, value_name = "PATH")]
        ssmm_bin: Option<PathBuf>,
        /// Actually write the drop-in and run `systemctl daemon-reload`.
        /// Without this flag the drop-in is printed to stdout.
        #[arg(long)]
        apply: bool,
    },
    /// Exec a command with SSM parameters injected as env vars (no .env on disk)
    ///
    /// Resolves parameters the same way as `sync` (app + shared overlay +
    /// include-tag overlay), then replaces the current process with the given
    /// command (execvp). Values never touch the filesystem. Parent environment
    /// variables are inherited; SSM values overlay them.
    Exec {
        #[arg(long)]
        app: Option<String>,
        /// Skip /<prefix>/shared/* overlay (default: included)
        #[arg(long)]
        no_shared: bool,
        /// Also include parameters matching tag (repeatable)
        #[arg(long = "include-tag", action = ArgAction::Append, value_name = "KEY=VALUE")]
        include_tags: Vec<String>,
        /// Exit with non-zero status when any shared / tag key is overridden
        /// by an app-level key (instead of just warning to stderr)
        #[arg(long)]
        strict: bool,
        /// Command and arguments to exec (use `--` before the command so
        /// flags destined for the child are not consumed by ssmm)
        #[arg(
            trailing_var_arg = true,
            allow_hyphen_values = true,
            required = true,
            num_args = 1..,
            value_name = "CMD"
        )]
        cmd: Vec<String>,
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
pub enum TagAction {
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
