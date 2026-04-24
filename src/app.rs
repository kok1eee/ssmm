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

/// List / Sync / Exec 用。空 Vec なら CWD から単一 app を推定、
/// 複数指定なら順序保持で返す (重複は除去、値は trim)。
pub fn resolve_apps(apps: Vec<String>) -> Result<Vec<String>> {
    if apps.is_empty() {
        return Ok(vec![detect_app_from_cwd()?]);
    }
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::with_capacity(apps.len());
    for a in apps {
        let a = a.trim().to_string();
        if a.is_empty() {
            return Err(anyhow!("--app received empty value"));
        }
        if seen.insert(a.clone()) {
            out.push(a);
        }
    }
    Ok(out)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_apps_preserves_order() {
        let out = resolve_apps(vec!["a".into(), "b".into(), "c".into()]).unwrap();
        assert_eq!(out, vec!["a", "b", "c"]);
    }

    #[test]
    fn resolve_apps_dedupes_keeping_first_occurrence() {
        let out = resolve_apps(vec!["a".into(), "b".into(), "a".into(), "c".into()]).unwrap();
        assert_eq!(out, vec!["a", "b", "c"]);
    }

    #[test]
    fn resolve_apps_trims_whitespace() {
        let out = resolve_apps(vec!["  a  ".into(), "b".into()]).unwrap();
        assert_eq!(out, vec!["a", "b"]);
    }

    #[test]
    fn resolve_apps_rejects_empty_value() {
        let err = resolve_apps(vec!["a".into(), "".into()]).unwrap_err();
        assert!(err.to_string().contains("empty"));
    }

    #[test]
    fn resolve_apps_rejects_whitespace_only_value() {
        let err = resolve_apps(vec!["a".into(), "   ".into()]).unwrap_err();
        assert!(err.to_string().contains("empty"));
    }
}
