# ssmm — AWS SSM Parameter Store helper for team-scoped `.env` sync

[![build](https://img.shields.io/badge/build-cargo-orange)]() [![license](https://img.shields.io/badge/license-MIT-blue)]()

A small Rust CLI that treats AWS SSM Parameter Store as the source of truth
for a team's `.env` files, with a flat-key convention and tag-based overlays.

`ssmm` is intentionally narrow-scoped: it assumes you run Linux services
(typically via systemd `ExecStartPre`) that consume a generated `.env` file
with `EnvironmentFile=`. If that matches your setup, the tool is opinionated
enough to remove a lot of shell-script boilerplate.

## Why another SSM wrapper?

Existing tools (e.g. [chamber](https://github.com/segmentio/chamber)) inject
secrets as env vars at `exec` time. `ssmm` instead **materializes a `.env`
file** on disk (mode 0600) that systemd loads via `EnvironmentFile=`. That
makes it a drop-in replacement for plaintext `.env` in existing systemd-based
deployments without changing the apps themselves.

Other opinions baked in:

- Parameters live under `/<team>/<app>/<key>` — the first segment is your
  team namespace (for IAM policy scoping), the second is the app, and the key
  is flat (`kintone-api-token`, not `kintone/api/token`).
- `SecureString` vs `String` is auto-detected from the key name (conservative:
  unknown keys default to `SecureString`). Only structural-looking suffixes
  (`_path` / `_dir` / `_channel` / `_name` / `_host` / `_port` / `_region` /
  `_endpoint`) map to `String`. **`_url` is NOT in the safe list** since
  URLs commonly embed credentials (e.g. `postgres://user:pass@host/db`,
  Slack webhook URLs) — URL-bearing keys stay `SecureString` by default.
  Override per key with `--plain KEY` if you really need plaintext.
- Each parameter is automatically tagged `app=<app>` so you can filter
  cross-namespace by tag later.

## Install

Requires Rust 1.77+ (or whatever supports `edition = "2024"`).

```bash
cargo install ssmm          # from crates.io
# or
cargo install --git https://github.com/kok1eee/ssmm
```

Your IAM role needs: `ssm:PutParameter`, `ssm:GetParametersByPath`,
`ssm:GetParameters`, `ssm:DescribeParameters`, `ssm:DeleteParameter(s)`,
`ssm:AddTagsToResource`, `ssm:RemoveTagsFromResource`,
`ssm:ListTagsForResource`. SSM `SecureString` uses the AWS-managed key
(`alias/aws/ssm`) by default.

## Configure your team's prefix

```bash
# option 1: env var (recommended for systemd services)
export SSMM_PREFIX_ROOT=/myteam

# option 2: per-invocation flag
ssmm --prefix /myteam list --all

# default (no config) is /amu-revo
```

All subcommands operate under this root prefix. Parameters end up at
`/<prefix>/<app>/<key>`.

## Quick tour

```bash
# Put a whole .env file
cd your-app/
ssmm put --env .env
# ↳ /myteam/your-app/kintone-api-token (SecureString)
# ↳ /myteam/your-app/slack-channel     (String)

# List (CWD auto-detects app name via basename)
ssmm list
ssmm list --keys-only
ssmm list --all                    # across every app under /myteam
ssmm list --tag env=prod

# Sync SSM → .env (systemd ExecStartPre friendly)
ssmm sync --out ./.env
# wrote 10 variables to ./.env (mode 0600)

# Show one
ssmm show kintone-api-token

# Manage tags on an existing parameter
ssmm tag add kintone-api-token shared=true owner=backend
ssmm tag list kintone-api-token
ssmm tag remove kintone-api-token owner

# Dashboard of every app namespace
ssmm dirs

# Find duplicates (same key across apps, or identical values)
ssmm check --duplicates --values

# Migrate parameters between prefixes
ssmm migrate /old-prefix/app /myteam/app --delete-old
```

## systemd integration

```ini
# ~/.config/systemd/user/myapp.service
[Service]
Environment=SSMM_PREFIX_ROOT=/myteam
ExecStartPre=/home/you/.cargo/bin/ssmm sync --app myapp --out /opt/myapp/.env
EnvironmentFile=/opt/myapp/.env
ExecStart=/opt/myapp/run.sh
```

`ssmm sync` is idempotent: if the generated content matches the existing
file byte-for-byte, it's a no-op (`ssmm: no change`).

## Shared namespace and tag overlays

Values shared across multiple apps have two expressions in `ssmm`:

```bash
# Put a cross-app value directly under /<prefix>/shared/*
ssmm put --app shared --env /path/shared.env

# Or tag an existing per-app parameter as shared
ssmm tag add kintone-api-token shared=true

# sync automatically overlays /<prefix>/shared/* (disable with --no-shared)
# and any tag-matched parameter via --include-tag
ssmm sync --include-tag shared=true
```

Precedence when the same key name appears in multiple layers:
**app > include-tag > shared**. Conflicts are logged to stderr.

## Auto-detection

When `--app` is omitted, `ssmm` picks the name from the current directory:

- `/home/you/services/my_api/` → `my-api` (snake_case → dash-case)
- `/home/you/services/billing-svc/` → `billing-svc`

Override with `--app <name>` any time.

## Concurrency and throttling

SSM's `PutParameter` has a low per-account TPS (~3/s for standard parameters).
`ssmm` caps concurrent writes to 3 and uses AWS SDK adaptive retry
(`max_attempts=10`), so a 300-parameter bulk import completes without manual
backoff.

## Comparison

|                         | ssmm       | chamber | dotenv-vault |
|-------------------------|------------|---------|--------------|
| Backend                 | AWS SSM PS | AWS SSM PS / S3 | hosted |
| Output model            | `.env` file | env vars at exec | `.env.vault` file |
| systemd `EnvironmentFile` | ✅ native | needs `chamber exec` | no |
| **Secrets materialized on disk** | **⚠️ yes (mode 0600)** | **no** (exec injection) | encrypted at rest |
| Key namespace convention | `<team>/<app>/<key>` | `<service>/<key>` | env profile |
| Tag management          | ✅ (`tag add/remove/list`) | — | — |
| Cross-app shared values | `/shared/` + tag overlay | — | — |
| Language                | Rust | Go | Node.js |

> **Security tradeoff**: `ssmm sync` writes decrypted SecureString values
> to a local file (mode 0600). This is a drop-in for plaintext `.env`
> workflows, not a hardened secret manager. If your threat model includes
> host compromise or backup exfiltration, prefer `chamber exec`-style
> injection (values live only in process memory). `ssmm` buys you systemd
> `EnvironmentFile=` compatibility and central SSM management at the cost
> of plaintext-on-disk during process lifetime.

## License

MIT. See [LICENSE](./LICENSE).
