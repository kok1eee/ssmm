# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-04-22

Initial release.

### Added

- `ssmm put` — bulk put from `.env` file or inline `KEY=VALUE` pairs, with
  conservative SecureString auto-detection (unknown keys default to secure;
  `_path` / `_url` / `_channel` / `_name` / `_host` / `_port` / `_region` /
  `_endpoint` / `_dir` suffixes map to String; `webhook` overrides to secure)
- `ssmm sync` — regenerate a `.env` file (mode 0600) from
  `/<prefix>/<app>/*`, with automatic overlay of `/<prefix>/shared/*`
  (opt out via `--no-shared`) and tag-based overlays via
  `--include-tag k=v` (repeatable). Precedence: app > include-tag > shared.
  Conflicts logged to stderr. Idempotent: same content = no write
- `ssmm list` — listing with CWD-auto-detection (basename snake_case →
  dash-case), `--all` across every app, `--keys-only`, `--tag k=v` filter
- `ssmm show` — read a single parameter (with decryption)
- `ssmm dirs` — summary of every app namespace under the prefix root
- `ssmm migrate` — bulk move parameters between prefixes, with optional
  `--delete-old`
- `ssmm delete` — single or recursive prefix delete with confirm prompt
- `ssmm check --duplicates` — cross-app trailing-key collision report
- `ssmm check --values` — identical-value grouping with SHA-256 mask
  (reveal actuals with `--show-values`)
- `ssmm tag add/remove/list` — post-hoc tag management on existing
  parameters. `app` tag is reserved and cannot be added/removed/overwritten
  by user
- Configurable prefix root via `--prefix` CLI flag or `SSMM_PREFIX_ROOT`
  env var (default: `/amu-revo`)
- Key `app=<app>` tag is automatically attached on `put` / `migrate`
- Empty `.env` values are skipped with a warning (SSM rejects empty
  strings)

### Reliability

- `WRITE_CONCURRENCY=3` (buffer_unordered) to respect SSM PutParameter's
  low TPS cap
- `aws-config` adaptive retry with `max_attempts=10` for automatic
  throttling backoff
- Parallel `get_parameters_by_path` + `names_filtered_by_tags` in `sync`
  (up to 3 concurrent SSM requests per invocation)
- SIGPIPE default so `ssmm list --all | head` no longer panics

### Docs

- README (English) with chamber / dotenv-vault comparison,
  systemd `ExecStartPre` integration example, and subcommand reference
- MIT license
