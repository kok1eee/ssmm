use anyhow::{Context, Result, anyhow, bail};
use aws_sdk_ssm::Client;
use aws_sdk_ssm::types::ParameterType;
use colored::Colorize;
use std::collections::HashSet;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use crate::app::app_prefix;
use crate::cli::{MigrateToExecArgs, OnboardArgs};
use crate::config::prefix_root;
use crate::env_map::{parse_tags, read_env_file};
use crate::ssm::{TypeReason, build_param_name, get_parameters_by_path, resolve_type};
use crate::systemd::{SystemdScope, build_drop_in};

use super::migrate_to_exec::cmd_migrate_to_exec;
use super::put::put_kvs;

struct OnboardPlan<'a> {
    app: &'a str,
    prefix: &'a str,
    kvs: &'a [(String, String)],
    plain_all: bool,
    plain_keys: &'a HashSet<String>,
    secure_keys: &'a HashSet<String>,
    extra_tags: &'a [(String, String)],
    existing_collisions: &'a [String],
    overwrite: bool,
    drop_in_path: &'a Path,
    drop_in_content: &'a str,
    revert_cmd: &'a str,
}

/// Pure formatter for onboard dry-run output. No `Client`, no SSM calls —
/// callable from tests to verify the "never leak values to stdout" property.
fn format_onboard_plan(plan: &OnboardPlan) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "# dry-run: onboard app={} with {} key(s)",
        plan.app,
        plan.kvs.len()
    );
    let _ = writeln!(out);

    if !plan.existing_collisions.is_empty() {
        let verb = if plan.overwrite {
            "WILL OVERWRITE"
        } else {
            "WOULD CONFLICT WITH"
        };
        let _ = writeln!(
            out,
            "# {} {} existing SSM key(s):",
            verb,
            plan.existing_collisions.len()
        );
        for n in plan.existing_collisions {
            let _ = writeln!(out, "#   {}", n);
        }
        let _ = writeln!(out);
    }

    let _ = writeln!(out, "# [1/2] put {} key(s) to {}:", plan.kvs.len(), plan.prefix);
    let tag_str = if plan.extra_tags.is_empty() {
        format!("[app={}]", plan.app)
    } else {
        let extras = plan
            .extra_tags
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join(", ");
        format!("[app={}, {}]", plan.app, extras)
    };
    for (k, v) in plan.kvs {
        let name = build_param_name(plan.prefix, k);
        let (ptype, reason) = resolve_type(k, plan.plain_all, plan.plain_keys, plan.secure_keys);
        let type_label = match ptype {
            ParameterType::SecureString => "SecureString",
            _ => "String",
        };
        // 値そのものは絶対に出さない (value-leak 回避)。len() のみ出力。
        // env key (UPPER_SNAKE) と SSM name (kebab-case) の両方を出すと、
        // 新規ユーザーに命名規則が見え、mapping 誤認のリスクを減らせる。
        let _ = writeln!(
            out,
            "  + {} → {} ({} [{}], len={}) {}",
            k,
            name,
            type_label,
            TypeReason::label(reason),
            v.len(),
            tag_str
        );
    }
    let _ = writeln!(out);

    let _ = writeln!(
        out,
        "# [2/2] write drop-in to {} + systemctl daemon-reload",
        plan.drop_in_path.display()
    );
    let _ = writeln!(out, "# revert: {}", plan.revert_cmd);
    let _ = writeln!(out);
    let _ = write!(out, "{}", plan.drop_in_content);

    let _ = writeln!(out);
    let _ = writeln!(out, "# apply with: `ssmm onboard ... --apply`");
    out
}

pub async fn cmd_onboard(client: &Client, args: OnboardArgs) -> Result<()> {
    let OnboardArgs {
        unit,
        app,
        env,
        exec_cmd,
        plain_all,
        plain_keys,
        secure_keys,
        tags: raw_tags,
        system,
        keep_env_files,
        pre_execs,
        ssmm_bin,
        overwrite,
        apply,
    } = args;
    let prefix = app_prefix(&app);

    // Collision detection (below) must run against the SAME filtered set that
    // put_kvs will actually put. Filter empty values here so a trailing FOO=
    // in the .env doesn't show up as a spurious "would overwrite".
    let mut kvs = read_env_file(&env)?;
    let before = kvs.len();
    kvs.retain(|(_, v)| !v.is_empty());
    if kvs.len() < before {
        eprintln!(
            "  ({} key(s) skipped due to empty value)",
            before - kvs.len()
        );
    }
    if kvs.is_empty() {
        bail!("no key=value in {} after filtering empty values", env.display());
    }

    let plain_set: HashSet<String> = plain_keys.into_iter().collect();
    let secure_set: HashSet<String> = secure_keys.into_iter().collect();
    if let Some(c) = plain_set.intersection(&secure_set).next() {
        bail!(
            "key {:?} is listed in both --plain-key and --secure; pick one",
            c
        );
    }
    let extra_tags = parse_tags(&raw_tags)?;
    if extra_tags.iter().any(|(k, _)| k == "app") {
        bail!("`app` tag is reserved; do not pass --tag app=...");
    }

    // Collision check runs ALWAYS, including under --overwrite, so the dry-run
    // "WILL OVERWRITE N keys" banner shows destructive intent before --apply.
    let desired: HashSet<String> = kvs
        .iter()
        .map(|(k, _)| build_param_name(&prefix, k))
        .collect();
    let existing = get_parameters_by_path(client, &prefix).await?;
    let mut collisions: Vec<String> = existing
        .iter()
        .filter_map(|p| p.name())
        .filter(|n| desired.contains(*n))
        .map(|n| n.to_string())
        .collect();
    collisions.sort();

    if !collisions.is_empty() && !overwrite {
        bail!(
            "{} existing SSM key(s) under {} would be overwritten:\n  {}\n\n\
             Pass --overwrite to replace them (values will be SILENTLY replaced),\n\
             or `ssmm delete {} -r` first if you want a clean slate.",
            collisions.len(),
            prefix,
            collisions.join("\n  "),
            app
        );
    }

    let resolved_ssmm_bin = ssmm_bin
        .clone()
        .or_else(|| {
            std::env::var("HOME")
                .ok()
                .map(|h| PathBuf::from(h).join(".cargo/bin/ssmm"))
        })
        .ok_or_else(|| anyhow!("cannot resolve default ssmm bin path (HOME unset)"))?;
    if !resolved_ssmm_bin.is_absolute() {
        bail!("--ssmm-bin must be an absolute path: {:?}", resolved_ssmm_bin);
    }
    let scope = if system {
        SystemdScope::System
    } else {
        SystemdScope::User
    };
    let drop_in_dir = scope.drop_in_dir(&unit)?;
    let drop_in_path = drop_in_dir.join("exec-mode.conf");
    let drop_in_content = build_drop_in(
        &app,
        &exec_cmd,
        &keep_env_files,
        &pre_execs,
        &resolved_ssmm_bin,
        prefix_root(),
    );

    if !apply {
        let revert_cmd = format!(
            "rm {} && systemctl {} daemon-reload",
            drop_in_path.display(),
            scope.as_cli_flag()
        );
        let plan = OnboardPlan {
            app: &app,
            prefix: &prefix,
            kvs: &kvs,
            plain_all,
            plain_keys: &plain_set,
            secure_keys: &secure_set,
            extra_tags: &extra_tags,
            existing_collisions: &collisions,
            overwrite,
            drop_in_path: &drop_in_path,
            drop_in_content: &drop_in_content,
            revert_cmd: &revert_cmd,
        };
        print!("{}", format_onboard_plan(&plan));
        return Ok(());
    }

    println!(
        "{} putting {} key(s) to SSM (app={})",
        "[1/2]".bold(),
        kvs.len(),
        app
    );
    put_kvs(
        client,
        &kvs,
        &app,
        plain_all,
        &plain_set,
        &secure_set,
        &extra_tags,
    )
    .await
    .context("SSM put failed; systemd step was not attempted")?;

    println!();
    println!(
        "{} writing systemd drop-in + daemon-reload",
        "[2/2]".bold()
    );
    cmd_migrate_to_exec(MigrateToExecArgs {
        unit,
        app: app.clone(),
        exec_cmd,
        system,
        keep_env_files,
        pre_execs,
        ssmm_bin,
        apply: true,
    })
    .map_err(|e| {
        anyhow!(
            "SSM values WERE written, but systemd step failed: {}\n\
             Revert SSM with `ssmm delete {} -r` if you need to abort the onboarding.",
            e,
            app
        )
    })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{Cli, Command};
    use clap::Parser;

    #[test]
    fn onboard_parses_minimal() {
        let cli = Cli::try_parse_from([
            "ssmm",
            "--prefix",
            "/myteam",
            "onboard",
            "--unit",
            "myapp.service",
            "--app",
            "myapp",
            "--env",
            "/tmp/myapp.env",
            "--exec-cmd",
            "/usr/bin/echo hi",
        ])
        .expect("parse");
        match cli.command {
            Command::Onboard(args) => {
                assert_eq!(args.unit, "myapp.service");
                assert_eq!(args.app, "myapp");
                assert_eq!(args.env.to_str().unwrap(), "/tmp/myapp.env");
                assert_eq!(args.exec_cmd, "/usr/bin/echo hi");
                assert!(!args.apply, "--apply defaults to false");
                assert!(!args.overwrite, "--overwrite defaults to false");
            }
            _ => panic!("expected Onboard variant"),
        }
    }

    #[test]
    fn format_onboard_plan_never_leaks_values() {
        let secret = "super-secret-value-1234567890abcdef";
        let kvs = vec![
            ("API_KEY".to_string(), secret.to_string()),
            ("DB_HOST".to_string(), "localhost".to_string()),
        ];
        let empty_set = HashSet::new();
        let plan = OnboardPlan {
            app: "myapp",
            prefix: "/myteam/myapp",
            kvs: &kvs,
            plain_all: false,
            plain_keys: &empty_set,
            secure_keys: &empty_set,
            extra_tags: &[],
            existing_collisions: &[],
            overwrite: false,
            drop_in_path: Path::new("/home/me/.config/systemd/user/myapp.service.d/exec-mode.conf"),
            drop_in_content: "[Service]\nExecStart=/ssmm exec --app myapp -- /bin/true\n",
            revert_cmd: "rm ... && systemctl --user daemon-reload",
        };
        let out = format_onboard_plan(&plan);
        assert!(
            !out.contains(secret),
            "dry-run output leaked API_KEY value; full output:\n{}",
            out
        );
        // "localhost" is DB_HOST's value. Also must not appear in the plan.
        assert!(
            !out.contains("=localhost"),
            "dry-run output leaked DB_HOST value; full output:\n{}",
            out
        );
        assert!(out.contains("API_KEY"), "expected key name in output");
        assert!(out.contains("DB_HOST"), "expected key name in output");
        assert!(
            out.contains("SecureString"),
            "API_KEY should auto-detect as SecureString"
        );
        assert!(
            out.contains(&format!("len={}", secret.len())),
            "should show length instead of value"
        );
    }

    #[test]
    fn format_onboard_plan_collision_overwrite_warning() {
        let kvs = vec![("FOO".to_string(), "bar".to_string())];
        let collisions = vec![
            "/myteam/myapp/foo".to_string(),
            "/myteam/myapp/legacy-key".to_string(),
        ];
        let empty_set = HashSet::new();
        let plan = OnboardPlan {
            app: "myapp",
            prefix: "/myteam/myapp",
            kvs: &kvs,
            plain_all: false,
            plain_keys: &empty_set,
            secure_keys: &empty_set,
            extra_tags: &[],
            existing_collisions: &collisions,
            overwrite: true,
            drop_in_path: Path::new("/tmp/x.conf"),
            drop_in_content: "",
            revert_cmd: "rm /tmp/x.conf",
        };
        let out = format_onboard_plan(&plan);
        assert!(
            out.contains("WILL OVERWRITE 2"),
            "overwrite=true with collisions should say 'WILL OVERWRITE', got:\n{}",
            out
        );
        assert!(out.contains("/myteam/myapp/foo"));
        assert!(out.contains("/myteam/myapp/legacy-key"));
    }

    #[test]
    fn format_onboard_plan_collision_without_overwrite_warning() {
        let kvs = vec![("FOO".to_string(), "bar".to_string())];
        let collisions = vec!["/myteam/myapp/foo".to_string()];
        let empty_set = HashSet::new();
        let plan = OnboardPlan {
            app: "myapp",
            prefix: "/myteam/myapp",
            kvs: &kvs,
            plain_all: false,
            plain_keys: &empty_set,
            secure_keys: &empty_set,
            extra_tags: &[],
            existing_collisions: &collisions,
            overwrite: false,
            drop_in_path: Path::new("/tmp/x.conf"),
            drop_in_content: "",
            revert_cmd: "rm /tmp/x.conf",
        };
        let out = format_onboard_plan(&plan);
        assert!(
            out.contains("WOULD CONFLICT WITH 1"),
            "overwrite=false should say 'WOULD CONFLICT WITH', got:\n{}",
            out
        );
    }
}
