# ssmm — AWS SSM Parameter Store helper for team-scoped `.env` sync

[![build](https://img.shields.io/badge/build-cargo-orange)]() [![license](https://img.shields.io/badge/license-MIT-blue)]()

📖 **English** · [日本語](README.ja.md)

A small Rust CLI that treats AWS SSM Parameter Store as the source of truth
for a team's `.env` files, with a flat-key convention and tag-based overlays.

`ssmm` is intentionally narrow-scoped: it assumes you run Linux services
(typically via systemd `ExecStartPre`) that consume a generated `.env` file
with `EnvironmentFile=`. If that matches your setup, the tool is opinionated
enough to remove a lot of shell-script boilerplate.

## Why another SSM wrapper?

Two delivery modes, same prefix convention and overlay rules:

- **`ssmm sync`** materializes a `.env` file (mode 0600) that systemd loads
  via `EnvironmentFile=`. Drop-in replacement for plaintext `.env` with zero
  app-side changes.
- **`ssmm exec`** injects SSM values directly into a child process's
  environment via `execvp` — no file on disk. Use when your threat model
  disallows plaintext secrets on the filesystem.

See [Security model](#security-model) for the tradeoff.

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

**ssmm requires an explicit prefix** — set it once and forget it:

```bash
# option 1: env var (recommended for systemd services)
export SSMM_PREFIX_ROOT=/myteam

# option 2: per-invocation flag
ssmm --prefix /myteam list --all
```

If neither is set, `ssmm` exits with:
```
Error: no prefix configured. Pass --prefix /<your-team> or set $SSMM_PREFIX_ROOT=/<your-team>.
```

All subcommands operate under this root prefix. Parameters end up at
`/<prefix>/<app>/<key>`.

## Quick tour

```bash
# Put a whole .env file (CWD basename becomes <app>, snake_case → dash-case)
cd your-app/
ssmm put --env .env
# ↳ /myteam/your-app/kintone-api-token (SecureString [auto: default], len=...)
# ↳ /myteam/your-app/slack-channel     (String [auto: suffix], len=...)

# Override the type per key when the heuristic gets it wrong
ssmm put --env .env --secure DATABASE_URL --secure SENTRY_DSN
ssmm put --env .env --plain-key METRICS_URL --plain-key PUBLIC_HOST
ssmm put --env .env --plain-all                  # everything String (public-config apps)

# List (CWD auto-detects app name via basename)
ssmm list
ssmm list --keys-only
ssmm list --all                                  # across every app under /myteam
ssmm list --tag env=prod

# Sync SSM → .env (systemd ExecStartPre friendly, mode 0600, idempotent)
ssmm sync --out ./.env
# ssmm: wrote 10 variables to ./.env (app=10, shared=0, tag=0)

# Strict mode: exit non-zero if a shared / tag key is overridden by an app key
# (good for systemd ExecStartPre — you want the service to FAIL, not silently diverge)
ssmm sync --out ./.env --strict

# Or skip the .env file entirely — SSM → process env directly (chamber-style).
# Parent env is inherited; SSM values overlay. Values never touch disk.
ssmm exec -- ./run.sh --flag value       # use `--` so child flags aren't eaten
ssmm exec --app myapp --include-tag shared=true -- python -m myapp
# stderr: ssmm: exec ./run.sh with 10 variables (app=10, shared=0, tag=0)

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

# Migrate parameters — three safe steps (SSM has no soft-delete; go slow)
ssmm migrate /old-prefix/app /myteam/app                      # step 1: copy only
ssmm migrate /old-prefix/app /myteam/app --delete-old         # step 2: dry-run + backup dump
                                                              #   → /tmp/ssmm-migrate-backup-<ts>.json
ssmm migrate /old-prefix/app /myteam/app --delete-old --confirm  # step 3: actually delete sources
```

## Migrating an existing sync unit to exec mode

If you already have units running in sync mode (`ExecStartPre=ssmm sync ...` +
`EnvironmentFile=...env`) and want to switch to exec mode, generate the
drop-in with `ssmm migrate-to-exec` instead of hand-editing:

```bash
# dry-run (default): prints the proposed drop-in
ssmm migrate-to-exec \
  --unit myapp.service \
  --app myapp \
  --exec-cmd "/usr/bin/uv run python app.py --mode prod" \
  --keep-env-file /etc/defaults/common \
  --pre-exec "/usr/bin/playwright install chromium"

# actually write the drop-in and reload systemd
ssmm migrate-to-exec ... --apply
```

- `--exec-cmd` is the command to run after SSM injection. Paste the
  existing `ExecStart=` value from `systemctl cat <unit>` verbatim; ssmm
  deliberately does not auto-parse systemd's output since `show` / `cat`
  format differs across versions and drop-in resets.
- `--keep-env-file PATH` preserves non-SSM `EnvironmentFile=` entries
  (e.g. a machine-wide PATH setup). Everything else is cleared so the
  old `.env` stops being read.
- `--pre-exec CMD` repopulates `ExecStartPre=` after clearing it; useful
  when the original `ExecStartPre` mixed `ssmm sync` with other prep
  steps (playwright install, cache warm-up) — list only the steps you
  still need.
- `--apply` writes `<drop-in-dir>/exec-mode.conf` and runs
  `systemctl [--user|--system] daemon-reload`. Without `--apply` it's a
  pure stdout dry-run.
- **Revert is one command**: `rm <drop-in> && systemctl daemon-reload`.
- Tested against sdtab-managed units; the generated drop-in coexists
  with sdtab's own `<unit>.d/v2-syslog-identifier.conf` style drop-ins.
  If you later run `sdtab upgrade`, verify `exec-mode.conf` survives —
  report back if it doesn't.
- **`--cwd-app` (v0.7.0+)**: emit `WorkingDirectory=<cwd>` and drop
  `--app <app>` from the generated `ExecStart=`. The running `ssmm`
  auto-detects the app from the CWD basename, so the drop-in gets
  shorter and sdtab tables stop having to repeat the app name in the
  `cmd:` field. Run `ssmm migrate-to-exec --cwd-app` from inside the
  app's repo directory (the path you'd `cd` into) — that path becomes
  the drop-in's `WorkingDirectory=`.

  ```bash
  cd ~/amu-tazawa-scripts/hikken_schedule       # CWD basename = hikken_schedule → app hikken-schedule
  ssmm migrate-to-exec \
    --unit sdtab-hikken-bashtv.service \
    --app hikken-schedule \
    --exec-cmd "/home/ec2-user/.local/share/mise/shims/uv run python main_spreadsheet.py --mode bashtv" \
    --pre-exec "/home/ec2-user/.local/bin/uv run playwright install chromium" \
    --cwd-app --apply
  ```

  Resulting drop-in `ExecStart=` becomes:
  ```
  WorkingDirectory=/home/ec2-user/amu-tazawa-scripts/hikken_schedule
  ExecStart=/home/ec2-user/.cargo/bin/ssmm exec -- /home/ec2-user/.local/share/mise/shims/uv run python main_spreadsheet.py --mode bashtv
  ```

## Onboarding a greenfield app in one command

`ssmm onboard` combines `put --env <file>` and `migrate-to-exec` for apps
that are not yet in SSM. It reads the `.env`, puts each key, generates
the systemd drop-in, and runs `daemon-reload` — all from one invocation.

```bash
# dry-run (default): prints put plan + drop-in preview, reads no files
ssmm onboard \
  --unit myapp.service \
  --app myapp \
  --env ./myapp.env \
  --exec-cmd "/usr/bin/uv run python app.py --mode prod" \
  --keep-env-file /etc/defaults/common \
  --pre-exec "/usr/bin/playwright install chromium"

# actually put + write drop-in + daemon-reload
ssmm onboard ... --apply
```

- **Default is fail-if-any-key-exists.** Running `onboard` twice won't
  silently overwrite a secret you rotated between runs. Pass
  `--overwrite` to opt into replace-existing semantics. Dry-run with
  `--overwrite` still lists the colliding keys under a
  `# WILL OVERWRITE` header so destructive intent is visible.
- Empty values in the `.env` are filtered out (matching `put`'s
  behaviour), so trailing `FOO=` lines don't trigger spurious
  "would overwrite" noise.
- Values never appear in dry-run output (names and `len=N` only);
  there is a snapshot test pinning this property.
- **If apply fails partway** — SSM put succeeds but `daemon-reload`
  fails — the error tells you to `ssmm delete <app> -r` to revert the
  SSM half. The systemd drop-in if written can be removed by
  `rm <path>` (shown in the error).
- **Use `migrate-to-exec` instead** when the app is already in SSM and
  you only need to switch modes. `onboard`'s default-fail guard will
  block you from double-putting.
- **`--cwd-app` (v0.7.0+)** works the same as on `migrate-to-exec`:
  the generated drop-in gets `WorkingDirectory=<cwd>` and the
  `ExecStart=` omits `--app`, so the `cmd:` column in a sdtab table
  no longer needs to repeat the app slug. Run `ssmm onboard --cwd-app`
  from inside the app's repo directory.

## systemd integration

Two shapes, pick based on threat model. Both work with user-scoped
systemd units (as shown below) and system units alike.

```ini
# (a) sync-mode — drops a mode-0600 .env next to the app, then starts it.
# Existing apps that read EnvironmentFile= work unchanged.
# ~/.config/systemd/user/myapp.service
[Service]
Environment=SSMM_PREFIX_ROOT=/myteam
ExecStartPre=/home/you/.cargo/bin/ssmm sync --app myapp --out /opt/myapp/.env
EnvironmentFile=/opt/myapp/.env
ExecStart=/opt/myapp/run.sh
```

```ini
# (b) exec-mode — no .env on disk; ssmm exec replaces itself with the app,
# passing SSM values via environ. Use when plaintext-on-disk is unacceptable.
[Service]
Environment=SSMM_PREFIX_ROOT=/myteam
ExecStart=/home/you/.cargo/bin/ssmm exec --app myapp -- /opt/myapp/run.sh
```

Notes:

- `ssmm sync` is idempotent: if the generated content matches the existing
  file byte-for-byte, it's a no-op (`ssmm: no change`).
- `ssmm exec` uses `execvp` so systemd sees the child process directly —
  `Type=simple` semantics, signal delivery, MainPID, and journal output all
  work as if systemd had started the app itself. No supervisor wrapper.
- Always put `--` before the child command in exec mode, so flags for the
  child (`--port`, `-H`, etc.) are not consumed by ssmm.

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

## Path values and portability

SSM stores parameter values as opaque bytes; `ssmm` does not expand
shell-style shortcuts like `~` on the way in or out. When a value is a
filesystem path, prefer the `$HOME`-relative form and let the consuming
app expand it at runtime:

```
# SSM parameter (portable)
GOOGLE_SERVICE_ACCOUNT_KEY_PATH=~/.credentials/service-account.json
```

```python
# Python — app side
import os
path = os.path.expanduser(os.getenv("GOOGLE_SERVICE_ACCOUNT_KEY_PATH") or "")
```

Why this matters: a hard-coded absolute path (e.g. `/home/ec2-user/...`)
in SSM works on that one host but silently breaks local dev on a
different `$HOME`. With `~` + `expanduser`, one SSM value serves every
environment. The same applies to path-like env vars in general — store
them portable, expand on read.

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

## Advanced tier and custom KMS key

Two opt-in knobs for cases where the defaults don't fit:

```bash
# Advanced tier: raises per-parameter limit from 4KB to 8KB.
# Required for certificates, PEM keys, or large JSON blobs.
# Costs $0.05/month per Advanced parameter (Standard is free).
ssmm --advanced put --env .env

# Custom KMS key: use a team-scoped CMK instead of the default
# AWS-managed key (`alias/aws/ssm`). Useful when you want to restrict
# decrypt permission to a subset of IAM principals via key policy.
ssmm --kms-key-id alias/myteam-ssm put --env .env
```

Notes:

- `--kms-key-id` only affects **newly-created** SecureString parameters.
  Existing parameters keep their original key (AWS does not allow
  re-keying in place — delete and recreate if you need to rotate).
- When migrating values that exceed 4KB, pass `--advanced` to
  `ssmm migrate` as well, or the copy step will fail with
  `ValidationException`.
- Tier downgrade (Advanced → Standard) is not supported by SSM; once
  Advanced, the parameter stays Advanced until deleted.

## Security model

`ssmm` is **not a hardened secret manager**. It's a `.env`-compatible
convenience layer over SSM. Decide based on your threat model, and pick
the right delivery mode (`sync` or `exec`).

### What `ssmm sync` actually does

`ssmm sync` calls `GetParametersByPath` with `--with-decryption`, writes
the resulting `KEY=VALUE` lines to the output path, and `chmod 0600`s
the file. Decrypted SecureString values live:

1. In memory on the host running `ssmm sync`
2. In the on-disk file (mode 0600, owner-only readable)
3. In the target process's environment after `systemd` reads
   `EnvironmentFile=` (→ readable via `/proc/<pid>/environ` to the same
   UID / root)

### What `ssmm exec` actually does

`ssmm exec` performs the same `GetParametersByPath` + decryption, but
then `execvp`s the child command with SSM values added to the inherited
environment. Decrypted SecureString values live:

1. In memory on the host during the SSM fetch
2. In the child process's environment (readable via `/proc/<pid>/environ`
   to the same UID / root)

Specifically, **step 2 of `sync` — the on-disk file — does not exist
under `exec`**. That is the primary difference between the two modes.

### What either mode protects against

- Accidental commit of plaintext `.env` to git (SSM is the source of truth)
- Unauthorized teammates who have SSM read permission but not host login
- Drift between hosts (central management vs hand-copied `.env` files)

### What neither mode protects against

- **Same-UID process snooping**: `/proc/<pid>/environ` is readable by
  same-UID processes (and root). Both modes expose values here once the
  app is running.
- **Host compromise**: attacker with filesystem read sees the process
  environment; under `sync` they also see the plaintext `.env`.
- **Systemd journal / CloudWatch log exfiltration**: `ssmm` is designed
  so that parameter **values never appear in error messages or log output**
  (only parameter names / counts / lengths / SHA-256 hashes). If you find
  a path that does leak values into stderr or journalctl, please open an
  issue — it's considered a bug. When integrating with CloudWatch /
  fluent-bit / Datadog logs, verify your own wrappers also preserve this
  discipline.

### What `exec` additionally protects against (vs `sync`)

- **Backup exfiltration**: no plaintext file, so `/opt/myapp/` backups
  don't leak secrets (unless the backup also captures process memory /
  `/proc`, which is uncommon).
- **Unauthorized file read by a different UID on the same host**: the
  sync'd `.env` is 0600 but still a file. `exec`-mode values only exist
  in the process's environ, protected by kernel process isolation.

### If your threat model is stricter than either mode

Consider tools that avoid even same-UID environ exposure:

- **HashiCorp Vault + agent** — short-lived leases, audit logs
- **SOPS + age/KMS** — encrypted-at-rest files, decrypt in-app only
- **Runtime secret brokers** (AWS Secrets Manager SDK called from within
  the app, rotated values, scoped to short-lived in-memory handling)

## Similar tools

I haven't benchmarked against the following in detail, so treat this
as orientation, not authoritative comparison. Issues / PRs welcome if
my positioning is wrong:

- **[chamber](https://github.com/segmentio/chamber)** — SSM-backed
  exec-time env injection. `ssmm exec` is the equivalent mode in `ssmm`
  (same underlying mechanism: decrypt + `execvp` + env overlay). `ssmm`
  adds a 3-segment prefix convention `/<team>/<app>/<key>`, a shared
  namespace, and tag overlays that chamber does not model.
- **[aws-vault](https://github.com/99designs/aws-vault)** — exec-time
  AWS credential injection. Different problem (IAM credentials vs. app
  secrets) but the same "no plaintext on disk" philosophy.
- **dotenv-vault** — hosted `.env.vault` format; not AWS-native.
- **HashiCorp Vault** — full secret lifecycle management (leasing,
  rotation, audit). Different tier of tool.

### Choose ssmm when

1. Your team keeps **multiple services** that share a secret namespace
   and you want a prefix convention (`/<team>/<app>/<key>`) with IAM
   policy scoping at the team boundary.
2. You want **both** `.env` file generation (for legacy `EnvironmentFile=`
   consumers) **and** chamber-style exec-time injection from one tool,
   with one IAM policy and one mental model.
3. You want CWD-auto-detection of the app name, a shared namespace for
   cross-app values, and tag-based overlays out of the box.

### Choose something else when

- You need secret rotation, leasing, or audit logs → HashiCorp Vault.
- You're not on AWS → SOPS + age, dotenv-vault, or Doppler.
- Your app needs to fetch secrets at runtime (not at process start) →
  call the AWS Secrets Manager / Parameter Store SDK directly from the
  app.

## Claude Code skill (bundled)

This repo ships a [Claude Code](https://docs.claude.com/en/docs/agents-and-tools/claude-code/overview)
skill at `.claude/skills/ssmm/SKILL.md` covering typical
`put → sync → systemd` workflows, migration patterns, and the
SecureString heuristic override knobs. If you use Claude Code, drop
it in by either symlink or copy:

```bash
# Option 1: symlink (updates follow git pull)
ln -s $(pwd)/.claude/skills/ssmm ~/.claude/skills/ssmm

# Option 2: copy (frozen at clone time)
cp -r .claude/skills/ssmm ~/.claude/skills/ssmm
```

Then `/ssmm` in a Claude Code session will expand into the workflow.

## License

MIT. See [LICENSE](./LICENSE).
