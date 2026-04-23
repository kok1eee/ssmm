# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-04-23

### Added

- Global `--write-concurrency N` / `--read-concurrency N` flags to tune
  bulk operations against AWS account-wide SSM TPS limits
  (default: 3 writes / 10 reads)
- `put --secure KEY` and `put --plain-key KEY` for per-key override of
  the SecureString heuristic (repeatable). `put` output now displays the
  classification reason: `auto: default` / `auto: suffix` /
  `forced: --secure` / `forced: --plain-key` / `forced: --plain-all`
- `sync --strict` exits non-zero when any shared / tag parameter is
  overridden by an app-level parameter (systemd services can detect
  the conflict as a failure instead of burying it in journalctl)
- `migrate --delete-old` now writes a JSON backup to
  `/tmp/ssmm-migrate-backup-<timestamp>.json` (mode 0600) and requires
  `--confirm` to actually delete source parameters. Without `--confirm`
  the command is a dry-run. SSM Parameter Store has no soft-delete, so
  this backup is the only recovery path if a migration is wrong

### Changed (breaking)

- `put --plain` (boolean, force all to String) renamed to
  `put --plain-all` to disambiguate from `--plain-key` (per-key override)
- `migrate --delete-old` alone no longer deletes; `--delete-old --confirm`
  is now required for the actual delete step

### Docs

- **Security model** independent section added to README, covering what
  `.env` materialization protects against vs doesn't (host compromise,
  backup exfiltration, `/proc/<pid>/environ` exposure) and pointers to
  chamber / aws-vault / SOPS for stricter threat models
- Removed the feature-comparison table. Replaced with a short
  "Similar tools" pointer noting chamber / aws-vault / dotenv-vault
  without claiming details I hadn't verified directly

### Dependencies

- `serde` + `serde_json` for `migrate --delete-old` backup JSON dump

## [0.1.1] - 2026-04-23

### Fixed

- `cargo install --git` URL in README now points to `kok1eee/ssmm`
  (previously incorrect `dmm-com/ssmm`). `Cargo.toml` `repository` /
  `homepage` metadata also corrected so crates.io links resolve

### Changed (security)

- `_url` suffix no longer falls through to `String` auto-detection.
  URLs routinely embed credentials (`postgres://user:pass@...`, Slack
  webhooks, Sentry DSNs); defaulting them to plaintext SSM storage was
  the #1 realistic foot-gun. `_url` keys now default to `SecureString`.
  Existing parameters in SSM are unaffected — only the `put`-time
  classification changes. Explicit override still available via `--plain KEY`
- `webhook` special-case is now redundant (all `_url` keys are already
  secure by default) but kept as a safety net

### Docs

- README comparison table gained a **"Secrets materialized on disk"**
  row making the ssmm-vs-chamber tradeoff explicit (ssmm: mode 0600
  plaintext file; chamber: exec-time env injection, no disk). A
  Security tradeoff callout was added so readers evaluate threat model
  before drop-in replacing chamber / aws-vault

### Tests

- `should_be_secure_url_keys_are_secure` covers DATABASE_URL,
  POSTGRES_URL, SLACK_WEBHOOK_URL, GOOGLE_SPREADSHEET_URL, SENTRY_DSN
- `should_be_secure_public_suffixes_map_to_string` updated to reflect
  the reduced safe list (added LOG_DIR / API_ENDPOINT; removed
  GOOGLE_SPREADSHEET_URL)

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
