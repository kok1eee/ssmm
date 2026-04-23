use anyhow::{Context, Result, anyhow, bail};
use colored::Colorize;
use std::path::PathBuf;

use crate::cli::MigrateToExecArgs;
use crate::config::prefix_root;
use crate::systemd::{SystemdScope, build_drop_in};

pub fn cmd_migrate_to_exec(args: MigrateToExecArgs) -> Result<()> {
    let MigrateToExecArgs {
        unit,
        app,
        exec_cmd,
        system,
        keep_env_files,
        pre_execs,
        ssmm_bin,
        apply,
    } = args;
    let scope = if system {
        SystemdScope::System
    } else {
        SystemdScope::User
    };

    let ssmm_bin = ssmm_bin
        .or_else(|| {
            std::env::var("HOME")
                .ok()
                .map(|h| PathBuf::from(h).join(".cargo/bin/ssmm"))
        })
        .ok_or_else(|| anyhow!("cannot resolve default ssmm bin path (HOME unset)"))?;
    if !ssmm_bin.is_absolute() {
        bail!("--ssmm-bin must be an absolute path: {:?}", ssmm_bin);
    }

    let drop_in_dir = scope.drop_in_dir(&unit)?;
    let drop_in_path = drop_in_dir.join("exec-mode.conf");

    let content = build_drop_in(
        &app,
        &exec_cmd,
        &keep_env_files,
        &pre_execs,
        &ssmm_bin,
        prefix_root(),
    );

    if !apply {
        println!(
            "# dry-run: would write {}",
            drop_in_path.display().to_string().bold()
        );
        println!(
            "# apply with: `ssmm migrate-to-exec ... --apply`  (writes file + daemon-reload)"
        );
        println!(
            "# revert with: `rm {} && systemctl {} daemon-reload`",
            drop_in_path.display(),
            scope.as_cli_flag()
        );
        println!();
        print!("{}", content);
        return Ok(());
    }

    if drop_in_path.exists() {
        eprintln!(
            "  {} {} already exists; overwriting",
            "warning:".yellow().bold(),
            drop_in_path.display()
        );
    }

    std::fs::create_dir_all(&drop_in_dir)
        .with_context(|| format!("mkdir -p {}", drop_in_dir.display()))?;
    std::fs::write(&drop_in_path, &content)
        .with_context(|| format!("write {}", drop_in_path.display()))?;
    println!("  ✓ wrote {}", drop_in_path.display());

    let status = std::process::Command::new("systemctl")
        .arg(scope.as_cli_flag())
        .arg("daemon-reload")
        .status()
        .context("spawn systemctl daemon-reload")?;
    if !status.success() {
        bail!(
            "`systemctl {} daemon-reload` exited with {}",
            scope.as_cli_flag(),
            status
        );
    }
    println!("  ✓ systemctl {} daemon-reload", scope.as_cli_flag());

    println!();
    println!(
        "revert: rm {} && systemctl {} daemon-reload",
        drop_in_path.display(),
        scope.as_cli_flag()
    );

    Ok(())
}
