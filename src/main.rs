mod app;
mod cli;
mod commands;
mod config;
mod env_map;
mod ssm;
mod systemd;
mod util;

use anyhow::{Result, anyhow};
use aws_sdk_ssm::Client;
use clap::Parser;

use crate::cli::{Cli, Command};
use crate::config::SSMM_ENV_VAR;

#[tokio::main]
async fn main() -> Result<()> {
    // stdout パイプ先が閉じても panic ではなく静かに終了させる (例: `ssmm list | head`)
    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }

    let cli = Cli::parse();

    let prefix = cli
        .prefix
        .clone()
        .or_else(|| std::env::var(SSMM_ENV_VAR).ok())
        .ok_or_else(|| {
            anyhow!(
                "no prefix configured. Pass --prefix /<your-team> or set \
                 ${SSMM_ENV_VAR}=/<your-team>. Example: `export {}=/myteam`.",
                SSMM_ENV_VAR
            )
        })?;
    config::init(
        prefix,
        cli.write_concurrency,
        cli.read_concurrency,
        cli.advanced,
        cli.kms_key_id,
    )?;

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
        } => commands::list::cmd_list(&client, app, all, keys_only, tags).await,
        Command::Put(args) => commands::put::cmd_put(&client, args).await,
        Command::Delete {
            target,
            app,
            yes,
            recursive,
        } => commands::delete::cmd_delete(&client, target, app, yes, recursive).await,
        Command::Show { key, app } => commands::show::cmd_show(&client, key, app).await,
        Command::Dirs => commands::dirs::cmd_dirs(&client).await,
        Command::Sync {
            app,
            out,
            no_shared,
            include_tags,
            strict,
        } => commands::sync::cmd_sync(&client, app, out, no_shared, include_tags, strict).await,
        Command::Exec {
            app,
            no_shared,
            include_tags,
            strict,
            cmd,
        } => commands::exec::cmd_exec(&client, app, no_shared, include_tags, strict, cmd).await,
        Command::MigrateToExec(args) => commands::migrate_to_exec::cmd_migrate_to_exec(args),
        Command::Migrate {
            old_prefix,
            new_prefix,
            delete_old,
            confirm,
        } => commands::migrate::cmd_migrate(&client, old_prefix, new_prefix, delete_old, confirm)
            .await,
        Command::Check {
            duplicates,
            values,
            show_values,
        } => commands::check::cmd_check(&client, duplicates, values, show_values).await,
        Command::Tag { action } => commands::tag::cmd_tag(&client, action).await,
        Command::Onboard(args) => commands::onboard::cmd_onboard(&client, args).await,
    }
}
