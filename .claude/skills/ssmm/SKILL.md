---
name: ssmm
description: AWS SSM Parameter Store を source of truth にして平文 .env を脱却する OSS ワークフロー。`sync` モード (systemd の EnvironmentFile= 用に mode 0600 の .env を再生成) と `exec` モード (プロセス環境変数に直注入、ディスクに .env を残さない、chamber 互換) の 2 方式を提供。`migrate-to-exec` で既存 sync unit を drop-in 生成で一括 exec 化可能。`onboard` で .env → SSM put + drop-in 生成 + daemon-reload を 1 コマンドで完結 (greenfield アプリ用、default-fail 衝突ガード付き)。team-scoped prefix (/<team>/<app>/<key>) で横断管理、SecureString / String 自動判定、shared / tag overlay、prefix 移行に使う。Rust CLI `ssmm` (crates.io) が必要。
---

Base directory for this skill: <cloned repo>/.claude/skills/ssmm

# ssmm: SSM-backed `.env` workflow (sync or exec)

このプロジェクト付属 skill。`ssmm` CLI の使い方と、typical な
`put → (sync | exec) → systemd` フローを示す。チーム内部固有の運用
ルールは含まない generic 版。

## いつ使うか

- 新しいアプリを systemd service 化するとき、最初から `.env` を SSM
  ベースにしたい
- 既存の平文 `.env` を SSM に移行したい
- 旧 prefix (`/<app>/` 直下など) を新 `/<team>/<app>/` 規約に揃えたい
- 複数アプリ間の重複キー / 重複値を棚卸ししたい
- SecureString で保存すべき key が誤って String で投入されていないか
  チェックしたい
- ディスクに平文 `.env` を一切残したくない (`exec` モード)

## ゴール

```
<project>/.env (平文、ディスク常駐、git commit 事故のリスク)
        ↓
SSM Parameter Store /<team>/<app>/* を source of truth にし、2 方式のいずれかで配信:

  (A) ssmm sync   → systemd の EnvironmentFile= 用に .env (mode 0600) を再生成
                    既存アプリ無改修、単体コマンドでも手動確認しやすい
  (B) ssmm exec   → プロセス環境変数に直注入して execvp、.env ファイル不要
                    ディスクに平文を残さない chamber 互換モード
```

どちらを選ぶかは脅威モデル次第 (README の **Security model** section
参照)。同じ prefix 規約 / SecureString 判定 / shared + tag overlay を
共有するため、後からもう一方に切り替えても SSM 側のデータはそのまま。

## 前提

- `ssmm` CLI install 済: `cargo install ssmm` か
  `cargo install --git https://github.com/kok1eee/ssmm`
- **`SSMM_PREFIX_ROOT` 環境変数 or `--prefix /<your-team>` 明示必須** (v0.3.0 以降)。
  未設定で呼ぶとエラーで停止する
- AWS IAM 権限: `ssm:PutParameter` / `GetParametersByPath` /
  `GetParameters` / `DescribeParameters` / `DeleteParameter(s)` /
  `AddTagsToResource` / `RemoveTagsFromResource` /
  `ListTagsForResource`
- SecureString は AWS managed key (`alias/aws/ssm`) デフォルト。
  カスタム CMK 使用時は `kms:Decrypt` 追加

## Prefix と命名規則

```
/<team>/<app>/<key>                → KEY
/<team>/<app>/<segment>/<key>      → SEGMENT_KEY
```

- `<team>`: チーム namespace (IAM policy を
  `arn:...:parameter/<team>/*` で一括付与可能にする)
- `<app>`: **dash-case** で統一 (`billing-api`, `auth-worker` など)
- CWD basename が snake_case (`hikken_schedule`) でも `ssmm` が自動で
  dash-case に変換して `--app` に使う
- `<key>`: フラット dash-case。`.env` 側の `KINTONE_API_TOKEN` は
  SSM 上 `kintone-api-token` として保存され、`sync` 時に
  `KINTONE_API_TOKEN` に戻る

## SecureString 自動判定

`ssmm put` は**保守的デフォルト** (unknown は SecureString):

- 末尾 `_PATH` / `_DIR` / `_CHANNEL` / `_NAME` / `_HOST` / `_PORT` /
  `_REGION` / `_ENDPOINT` → String
- **`_URL` は safe list に入っていない** (URL は credentials を含む
  ことが多い: `postgres://user:pass@host/db`, Slack webhook URL,
  Sentry DSN)
- それ以外 → SecureString

ヒューリスティックが不適切な時は per-key オーバーライド:

```bash
ssmm put --env .env --secure SENTRY_DSN --secure DATABASE_URL
ssmm put --env .env --plain-key PUBLIC_METRICS_URL
ssmm put --env .env --plain-all   # 全 String 強制 (public-only app)
```

`put` 出力に判定根拠が付く:
```
✓ /<team>/<app>/sentry-dsn (SecureString [forced: --secure], len=...)
✓ /<team>/<app>/log-dir    (String [auto: suffix], len=...)
```

## 手順

### 0. prefix 設定

```bash
export SSMM_PREFIX_ROOT=/<your-team>   # 一度 shell rc に入れると楽
# or: 毎回 `ssmm --prefix /<your-team> <subcmd>`
```

### 1. SSM 投入

```bash
cd <app-root>
ssmm put --env .env                    # CWD basename を <app> に使う
```

### 2. 検証

```bash
ssmm list                              # CWD 自動判定
ssmm list --keys-only
```

### 3. systemd に接続

脅威モデルで `sync` か `exec` を選ぶ。両方とも SSM 側のデータは同じ。

#### 3A. sync モード (.env を mode 0600 で再生成)

新規 wrapper:

```bash
# scripts/start-pre.sh
#!/usr/bin/env bash
set -euo pipefail
APP_ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$APP_ROOT"

export SSMM_PREFIX_ROOT=/<your-team>
ssmm sync --app <a> --out "$APP_ROOT/.env" --strict
# 後続: uv sync / playwright install 等あれば
```

systemd unit に:
```ini
[Service]
ExecStartPre=/opt/app/scripts/start-pre.sh
EnvironmentFile=/opt/app/.env
ExecStart=/opt/app/run.sh
```

#### 3B. exec モード (ディスクに .env を残さない)

ExecStart 自体を `ssmm exec` 経由に。execvp でプロセス置換するので、
systemd から見ると直接アプリが起動したのと同じ (MainPID / signals /
journal output そのまま機能):

```ini
[Service]
Environment=SSMM_PREFIX_ROOT=/<your-team>
ExecStart=/home/<user>/.cargo/bin/ssmm exec --app <a> --strict -- /opt/app/run.sh
# 子に渡す引数は `--` より後ろに。`-H` `--port` など子フラグは ssmm に吸われない
```

`EnvironmentFile=` は**書かない**。SSM 値はプロセス environ に直注入
される。親プロセス (systemd) から継承した env 変数も残るので、
`SSMM_PREFIX_ROOT` は `Environment=` で渡す。

#### 3C. sync → exec への移行自動化 (`ssmm migrate-to-exec`, v0.5.0+)

既存の sync モード unit を exec モードに切り替える drop-in を自動生成:

```bash
# dry-run: 提案 drop-in を stdout に出すだけ
ssmm migrate-to-exec \
  --unit <unit>.service \
  --app <ssm-app> \
  --exec-cmd "<現行 ExecStart= の値をそのまま貼る>" \
  --keep-env-file /<team 共通 env のパス> \
  --pre-exec "<残したい ExecStartPre をコマンド単位で列挙>"

# 確定: drop-in を書き込み + daemon-reload
ssmm migrate-to-exec ... --apply
```

- **`--exec-cmd` は必須**: `systemctl cat <unit>` を見て `ExecStart=` の
  右辺をそのまま `--exec-cmd "..."` に貼る。systemd の show/cat 出力は
  version 差があって parse が fragile なので、ssmm は自動解析しない。
- `--keep-env-file` は **SSM 非由来**の `EnvironmentFile=` を保持する
  (sdtab 共通 env など)。指定しないと全 EnvironmentFile= が外れる。
- `--pre-exec` は空白区切りコマンド。複数回指定で順序付き列挙。
  元の `ExecStartPre=` に `ssmm sync` 以外の前処理 (playwright install,
  キャッシュ warm 等) が混ざっていた場合、そちらだけ残す。
- **revert は 1 行**: `rm <drop-in> && systemctl --user daemon-reload`。
- sdtab 管理下の unit でも動作確認済 (drop-in が共存する)。ただし
  `sdtab upgrade` が走ったとき `exec-mode.conf` が温存されるかは
  バージョン依存なので、初回移行後 1 度 `sdtab upgrade` を走らせて
  survives するか軽く確認しておくと安心。

#### 3D. グリーンフィールド: `.env` → SSM + drop-in を 1 コマンド (`ssmm onboard`, v0.6.0+)

SSM にまだ投入していない新規アプリを `.env` 1 つから一発セットアップ:

```bash
# dry-run: put plan + drop-in プレビュー (SSM 衝突も列挙)
ssmm onboard \
  --unit <unit>.service \
  --app <ssm-app> \
  --env /path/to/<app>.env \
  --exec-cmd "<目的の ExecStart= 相当>" \
  --keep-env-file /<team 共通 env> \
  --pre-exec "<prep コマンド>"

# 確定: put + drop-in 書き込み + daemon-reload
ssmm onboard ... --apply
```

- **デフォルトは既存 key が 1 つでもあれば fail**。`ssmm put --secure` で
  ローテーションした値を silently 上書きする事故を防ぐガード。衝突した
  key 名は全列挙され、`--overwrite` か `ssmm delete <app> -r` を促す。
- `--overwrite` 時でも dry-run には `# WILL OVERWRITE N existing SSM key(s)`
  ヘッダーと該当 key 一覧が出るので、破壊的意図を見落とさない。
- 空値 (`EMPTY=`) は `put` と同じく事前にフィルタ。put には行かず、
  collision 判定からも除外される。
- 値は dry-run に一切出ない (`len=N` のみ)。snapshot test で pin 済み。
- **途中で失敗したら**: SSM put 成功後に daemon-reload が失敗した場合、
  エラーメッセージが `ssmm delete <app> -r` による revert 手順を示す。
  書いた drop-in は `rm <path>` で消せる (同じエラー内に path が出る)。
- **SSM に既にある app には使わない**: default-fail ガードで弾かれる。
  モード切替だけなら `migrate-to-exec` を使う。

### 4. 動作確認

```bash
systemctl --user start --no-block <service>
journalctl --user -u <service> --no-pager --since "1 minute ago" -n 20
# (sync モード)
#   ssmm: no change (N variables; ...)    ← 既存 .env と一致
#   ssmm: wrote N variables to ...        ← 初回 or SSM 変更あり
# (exec モード)
#   ssmm: exec /opt/app/run.sh with N variables (app=N, shared=0, tag=0)
```

`--strict` を付けておくと、shared / tag overlay の衝突が起きた時に
service が failure ステータスで止まる (journalctl で warning が埋も
れる事故を防ぐ)。

## 運用パターン

### 共有値 (複数アプリで同じ token)

2 通り:

```bash
# path-based: /<team>/shared/* に明示配置
ssmm put --env /path/shared.env --app shared

# tag-based: 既存 per-app parameter に shared=true を付ける
ssmm tag add kintone-api-token shared=true
```

`sync` はデフォルトで `/<team>/shared/*` を overlay する
(`--no-shared` で off)。tag-based は `--include-tag shared=true` で
取り込み。衝突時の優先順位: **app > include-tag > shared**。

### 棚卸し

```bash
ssmm dirs                              # 全 app namespace と件数
ssmm check --duplicates                # キー名重複 (同名 key が複数 app に)
ssmm check --values                    # 値一致グループ (SHA-256 マスク表示)
ssmm check --values --show-values      # 値を露出 (秘匿注意)
```

### 複数 unit の一括 migrate-to-exec

同じ SSM app を共有する unit 群 (sdtab の同一スクリプト + `--mode` 違い、
マルチテナント運用の worker 複製など) を一気に exec モードに切り替える流れ:

1. 先行 1 unit を `migrate-to-exec --apply` で移行、実行 or cron 発火で
   動作確認 (値注入 + Result=success)
2. 残り N unit をループで一括 `--apply`
3. 全 unit 安定稼働を確認したら元の `.env` と ExecStartPre の
   `ssmm sync` 行を除去 (下の cleanup セクション参照)

ループ例 (`ExecStart=` を `systemctl cat` から動的抽出し、unit ごとの
`--mode` 差分を自動で吸収):

```bash
APP=myapp
KEEP=/home/me/.config/common/env            # SSM 非由来の EnvironmentFile
PRE="/usr/bin/playwright install chromium"  # sync 以外で残したい ExecStartPre

for NAME in foo bar baz; do
  UNIT="sdtab-myapp-${NAME}.service"
  EXEC=$(systemctl --user cat "$UNIT" \
         | awk -F= '/^ExecStart=/ {sub(/^ExecStart=/, ""); print; exit}')
  ssmm migrate-to-exec \
    --unit "$UNIT" --app "$APP" \
    --exec-cmd "$EXEC" \
    --keep-env-file "$KEEP" \
    --pre-exec "$PRE" \
    --apply
done
```

- 先行 1 unit は手書き drop-in (または `migrate-to-exec` dry-run 出力を
  手で配置) でも良い。そちらと `migrate-to-exec` dry-run 出力が構造的に
  一致することを 1 度確認しておくと、バッチ結果も信頼できる。
- バッチ後は `systemctl --user status <UNIT>` で全 unit の
  `Drop-In: ... exec-mode.conf` を確認。または
  `systemctl --user list-unit-files 'sdtab-myapp-*.service' | ...` で
  grep 可能。

### rollout 完了後の cleanup (平文 .env 撲滅)

全 unit が 1 日以上安定稼働したら:

1. 旧 app 固有 `.env` を削除 (EnvironmentFile= は drop-in の reset で
   既に切れているが、ディスクから完全に消すのが本来の目的)
2. `ExecStartPre` に仕込んでいた `ssmm sync` 相当の行を削除 (playwright
   install など sync 以外の前処理は残す)
3. 再度全 unit を発火させ、失敗しないことを確認 (cron 発火まで待つか、
   手動 `systemctl --user start`)

この時点で app の秘密情報は SSM のみに存在し、ディスク (`.env`) にも
systemd の EnvironmentFile= にも現れない。

### prefix 移行 (旧→新)

**SSM には soft-delete がないので 3 段階で**:

```bash
# 1. copy のみ (旧は残る、safe)
ssmm migrate /old-prefix/app /<team>/app

# 2. --delete-old (単独では dry-run、backup JSON を /tmp に出力)
ssmm migrate /old-prefix/app /<team>/app --delete-old
# → /tmp/ssmm-migrate-backup-<ts>.json (mode 0600)

# 3. 確認後に実削除
ssmm migrate /old-prefix/app /<team>/app --delete-old --confirm
```

### タグ管理 (既存 parameter に後付け)

```bash
ssmm tag add <key> env=prod owner=backend criticality=high
ssmm tag list <key>
ssmm tag remove <key> criticality
```

`app` タグは `put` 時に自動付与され、`tag add/remove` では操作不可
(予約タグ)。

## Concurrency チューニング

SSM の PutParameter は per-account で TPS ~3/s (standard)。他の
プロセス (CI / 他チーム) と同時に叩くとスロットリングする:

```bash
ssmm --write-concurrency 1 put --env .env   # 他と同居時は 1 まで絞る
ssmm --read-concurrency 20 list --all       # read は余裕あるので上げる
```

adaptive retry (max 10 回) は自動。

## 検証チェックリスト

- [ ] `ssmm list` で想定 key 数が出る
- [ ] SecureString (🔒 アイコン) が secret 系 key に付いている
- [ ] `ssmm sync` 2 回目に `ssmm: no change (N variables)` (冪等)
- [ ] unit ファイルに `ExecStartPre=.../scripts/start-pre.sh` +
      `EnvironmentFile=.../.env` が揃う
- [ ] `systemctl --user start --no-block` 後 `Result=success`
- [ ] `.env` が mode 0600
- [ ] `.gitignore` に `.env*` 含まれる
- [ ] `ssmm check --duplicates` で意図しない横断重複がない

## トラブルシュート

| 症状 | 対処 |
|---|---|
| `Error: no prefix configured` | `export SSMM_PREFIX_ROOT=/<your-team>` or `--prefix /<your-team>` を追加 |
| `cannot determine CWD basename` | `--app <name>` を明示、あるいは `cd <project-dir>` してから呼ぶ |
| `warning: empty value, skipped: KEY` | `.env` 側の `KEY=` が空。SSM は空文字列 reject、意図していれば無視 |
| `ThrottlingException: Rate exceeded` | `--write-concurrency 1` に落とす。adaptive retry はすでに有効 |
| `.env` を手動で変えたのに `sync` で `no change` | ローカル .env は SSM と既に一致。意図的に regenerate したい時は `rm .env && ssmm sync --out .env` |
| systemd の cron 起動で `ssmm sync` が失敗 | `export SSMM_PREFIX_ROOT=...` が `start-pre.sh` に入っているか確認 |
| `sync --strict` で exit 非0 | shared / tag key が app-level で overridden。意図しない上書きなら key rename、意図通りなら `--strict` 外すか override を削除 |

## 将来拡張 (backlog)

- `ssmm verify` — SSM vs 実 `.env` の diff (CI pre-commit 用)
- `ssmm install` — `scripts/start-pre.sh` 雛形生成 (playwright / uv
  sync flag 付き)
- `ssmm tag add/remove` を bulk 化 (prefix 指定で配下一括 tag 付与)

issues: https://github.com/kok1eee/ssmm/issues
