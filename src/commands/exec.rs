use anyhow::{Result, anyhow};
use aws_sdk_ssm::Client;

use crate::app::resolve_app;
use crate::env_map::{build_env_map, parse_tags};

pub async fn cmd_exec(
    client: &Client,
    app: Option<String>,
    no_shared: bool,
    raw_include_tags: Vec<String>,
    strict: bool,
    cmd_and_args: Vec<String>,
) -> Result<()> {
    let app = resolve_app(app)?;
    let include_tags = parse_tags(&raw_include_tags)?;
    let merged = build_env_map(client, &app, no_shared, &include_tags, strict).await?;

    // clap の `required = true, num_args = 1..` で保証されるため、空なら設計バグ
    let (program, args) = cmd_and_args
        .split_first()
        .expect("clap enforces at least one CMD argument");

    eprintln!(
        "ssmm: exec {} with {} variables (app={}, shared={}, tag={})",
        program,
        merged.map.len(),
        merged.app_params_count,
        merged.shared_params_count,
        merged.tag_params_count
    );

    use std::os::unix::process::CommandExt;
    // exec() 成功時は制御が戻らない (プロセス置換)。失敗時のみ io::Error が返る。
    // 値流出を避けるため、エラー整形は program 名のみ含める (env 値は絶対に出さない)
    let err = std::process::Command::new(program)
        .args(args)
        .envs(&merged.map)
        .exec();
    Err(anyhow!("exec {}: {}", program, err))
}
