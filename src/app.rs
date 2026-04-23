use anyhow::{Result, anyhow};

use crate::config::prefix_root;
use crate::ssm::env_key_to_ssm_tail;

pub fn detect_app_from_cwd() -> Result<String> {
    let pwd = std::env::current_dir()?;
    let name = pwd
        .file_name()
        .ok_or_else(|| anyhow!("cannot determine CWD basename"))?
        .to_string_lossy()
        .into_owned();
    Ok(name.replace('_', "-"))
}

pub fn resolve_app(app: Option<String>) -> Result<String> {
    match app {
        Some(a) => Ok(a),
        None => detect_app_from_cwd(),
    }
}

pub fn app_prefix(app: &str) -> String {
    format!("{}/{}", prefix_root(), app)
}

pub fn resolve_param_name(key: &str, app: Option<String>) -> Result<String> {
    if key.starts_with('/') {
        return Ok(key.to_string());
    }
    Ok(format!(
        "{}/{}",
        app_prefix(&resolve_app(app)?),
        env_key_to_ssm_tail(key)
    ))
}
