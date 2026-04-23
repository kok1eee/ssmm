# ssmm — AWS SSM Parameter Store helper for team-scoped `.env` sync

[![build](https://img.shields.io/badge/build-cargo-orange)]() [![license](https://img.shields.io/badge/license-MIT-blue)]()

A small Rust CLI that treats AWS SSM Parameter Store as the source of truth
for a team's `.env` files, with a flat-key convention and tag-based overlays.

`ssmm` is intentionally narrow-scoped: it assumes you run Linux services
(typically via systemd `ExecStartPre`) that consume a generated `.env` file
with `EnvironmentFile=`. If that matches your setup, the tool is opinionated
enough to remove a lot of shell-script boilerplate.

## Why another SSM wrapper?

`ssmm` **materializes a `.env` file** on disk (mode 0600) that systemd
loads via `EnvironmentFile=`. That makes it a drop-in replacement for
plaintext `.env` in existing systemd-based deployments without changing
the apps themselves. See [Security model](#security-model) for the
disk-materialization tradeoff.

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

SSM's `PutParameter` has a low per-account TPS (~3/s for standard
parameters). `ssmm` defaults to `--write-concurrency=3` with AWS SDK
adaptive retry (`max_attempts=10`), so bulk imports complete without
manual backoff. Reads default to `--read-concurrency=10`. Both are
adjustable per invocation:

```bash
ssmm --write-concurrency 1 put --env .env     # tighter throttle-avoidance
ssmm --read-concurrency 20 list --all          # faster on high-limit accounts
```

## Security model

`ssmm` is **not a hardened secret manager**. It's a `.env`-compatible
convenience layer over SSM. Decide based on your threat model.

### What `ssmm sync` actually does

`ssmm sync` calls `GetParametersByPath` with `--with-decryption`, writes
the resulting `KEY=VALUE` lines to the output path, and `chmod 0600`s
the file. Decrypted SecureString values live:

1. In memory on the host running `ssmm sync`
2. In the on-disk file (mode 0600, owner-only readable)
3. In the target process's environment after `systemd` reads
   `EnvironmentFile=` (→ readable via `/proc/<pid>/environ` to the same
   UID / root)

### What this protects against

- Accidental commit of plaintext `.env` to git (SSM is the source of truth)
- Unauthorized teammates who have SSM read permission but not host login
- Drift between hosts (central management vs hand-copied `.env` files)

### What this does NOT protect against

- **Host compromise**: attacker with filesystem read on the host sees
  plaintext `.env` and the process environment
- **Backup exfiltration**: if you back up `/opt/myapp/` or `/home/<user>/`,
  plaintext secrets may end up in your backup storage
- **Same-host other processes under the same UID**: `/proc/<pid>/environ`
  is readable by same-UID processes

### If your threat model is stricter

Consider tools that never materialize decrypted values on disk:

- **[chamber](https://github.com/segmentio/chamber)** (Segment) — reads
  SSM at `exec` time and injects env vars; nothing on disk
- **[aws-vault](https://github.com/99designs/aws-vault)** — similar
  approach for AWS credentials
- **SOPS + age/KMS** — encrypted-at-rest files, decrypt-on-read

`ssmm`'s niche is specifically *systemd `EnvironmentFile=` drop-in
replacement for plaintext `.env`*. If you don't need that integration,
the tools above may fit your threat model better.

## Similar tools

I haven't benchmarked against the following in detail, so treat this
as orientation, not authoritative comparison. Issues / PRs welcome if
my positioning is wrong:

- **chamber** — exec-time env var injection, no on-disk file
- **aws-vault** — AWS credential focus, related design
- **dotenv-vault** — hosted `.env.vault` format

`ssmm`'s opinionated pieces (team-scoped prefix, flat-key convention,
tag overlays, shared namespace, CWD auto-detection) exist to remove
per-project shell boilerplate in systemd-heavy deployments. For other
deployment shapes the above may be a better fit.

## License

MIT. See [LICENSE](./LICENSE).
