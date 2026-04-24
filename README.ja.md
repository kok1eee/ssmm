# ssmm — チームスコープの `.env` 同期のための AWS SSM Parameter Store ヘルパー

[![build](https://img.shields.io/badge/build-cargo-orange)]() [![license](https://img.shields.io/badge/license-MIT-blue)]()

📖 [English](README.md) · **日本語**

AWS SSM Parameter Store をチームの `.env` ファイルの source of truth として
扱う小さな Rust 製 CLI。フラットなキー命名規則とタグベースのオーバーレイを
提供します。

`ssmm` は意図的にスコープを絞っています: systemd `ExecStartPre` 経由で生成した
`.env` ファイルを `EnvironmentFile=` で読み込む Linux サービス運用を前提と
しています。この構成に当てはまるなら、シェルスクリプトの定型句をかなり
削減できる程度には意見を持ったツールです。

## なぜ SSM wrapper を自作するのか

2 つの配送モード、同じ prefix 規約とオーバーレイルール:

- **`ssmm sync`**: systemd が `EnvironmentFile=` で読み込む `.env` ファイル
  (mode 0600) を生成。アプリ側の変更ゼロで平文 `.env` の drop-in 置き換え。
- **`ssmm exec`**: `execvp` 経由で SSM 値を子プロセスの environ に直接注入 —
  ディスクにファイルを残さない。脅威モデル上、ファイルシステムに平文 secret
  を置けない場合に使用。

トレードオフは [セキュリティモデル](#セキュリティモデル) を参照。

その他の設計判断:

- Parameter は `/<team>/<app>/<key>` 配下に配置 — 最初のセグメントがチーム
  namespace (IAM ポリシースコープ用)、2 番目がアプリ、キーはフラット
  (`kintone-api-token` であって `kintone/api/token` ではない)。
- `SecureString` vs `String` はキー名から自動判定 (保守的: 不明なキーは
  `SecureString` デフォルト)。構造的な意味を持つ suffix
  (`_path` / `_dir` / `_channel` / `_name` / `_host` / `_port` / `_region` /
  `_endpoint`) のみ `String` にマップされます。**`_url` は safe list に含め
  ていません** — URL はよく credentials を埋め込む (例: `postgres://user:pass@host/db`、
  Slack webhook URL) ため、URL を含むキーはデフォルトで `SecureString` のまま。
  本当に平文で保存したい場合はキー単位で `--plain KEY` で上書きしてください。
- 各 parameter には自動的に `app=<app>` タグが付与され、後から namespace を
  またいでタグで絞り込めます。

## インストール

Rust 1.77+ (または `edition = "2024"` をサポートするバージョン) が必要。

```bash
cargo install ssmm          # crates.io から
# または
cargo install --git https://github.com/kok1eee/ssmm
```

IAM ロールに必要な権限: `ssm:PutParameter`, `ssm:GetParametersByPath`,
`ssm:GetParameters`, `ssm:DescribeParameters`, `ssm:DeleteParameter(s)`,
`ssm:AddTagsToResource`, `ssm:RemoveTagsFromResource`,
`ssm:ListTagsForResource`。SSM `SecureString` はデフォルトで AWS マネージド
キー (`alias/aws/ssm`) を使用します。

## チームの prefix を設定

**ssmm は明示的な prefix を要求** — 一度設定すれば忘れていい:

```bash
# 方法 1: 環境変数 (systemd サービス向け推奨)
export SSMM_PREFIX_ROOT=/myteam

# 方法 2: 呼び出しごとのフラグ
ssmm --prefix /myteam list --all
```

どちらも設定されていない場合、`ssmm` は次のエラーで終了します:
```
Error: no prefix configured. Pass --prefix /<your-team> or set $SSMM_PREFIX_ROOT=/<your-team>.
```

全 subcommand はこの root prefix の下で動作します。Parameter は最終的に
`/<prefix>/<app>/<key>` に配置されます。

## クイックツアー

```bash
# .env ファイルをまとめて投入 (CWD basename が <app> になり、snake_case → dash-case)
cd your-app/
ssmm put --env .env
# ↳ /myteam/your-app/kintone-api-token (SecureString [auto: default], len=...)
# ↳ /myteam/your-app/slack-channel     (String [auto: suffix], len=...)

# ヒューリスティックが外れた場合にキー単位で型を上書き
ssmm put --env .env --secure DATABASE_URL --secure SENTRY_DSN
ssmm put --env .env --plain-key METRICS_URL --plain-key PUBLIC_HOST
ssmm put --env .env --plain-all                  # 全て String (公開 config 用アプリ)

# 一覧 (CWD から basename でアプリ名を自動判定)
ssmm list
ssmm list --keys-only
ssmm list --all                                  # /myteam 配下の全アプリを横断
ssmm list --tag env=prod

# SSM → .env 同期 (systemd ExecStartPre 向け、mode 0600、冪等)
ssmm sync --out ./.env
# ssmm: wrote 10 variables to ./.env (app=10, shared=0, tag=0)

# strict モード: shared / tag キーが app キーに上書きされたら非ゼロ exit
# (systemd ExecStartPre で有用 — 静かに分岐するより FAIL したい場面向け)
ssmm sync --out ./.env --strict

# .env ファイルを介さず SSM → プロセス environ に直接注入 (chamber スタイル)。
# 親 env は継承され、SSM 値がオーバーレイする。値はディスクに触れない。
ssmm exec -- ./run.sh --flag value       # `--` を付けて子のフラグが食われないように
ssmm exec --app myapp --include-tag shared=true -- python -m myapp
# stderr: ssmm: exec ./run.sh with 10 variables (app=10, shared=0, tag=0)

# Variant overlay — `--app` は repeatable。後の --app が key 衝突時に勝つので、
# 「common base + variant overlay」を重複なしで表現できる。`sync` / `list` も同じ構文。
ssmm exec --app knowledge-bot-common --app knowledge-bot-soumu -- /app/bin
# stderr: ssmm: exec /app/bin with 20 variables (apps=knowledge-bot-common:17,knowledge-bot-soumu:3, shared=0, tag=0)
# 優先度 (低 → 高): shared < include-tag < apps[0] < apps[1] < ... < apps[N]
# --strict で layer 間衝突 (app 同士含む) があれば exit 非 0。

# 1 件を表示
ssmm show kintone-api-token

# 既存 parameter のタグ管理
ssmm tag add kintone-api-token shared=true owner=backend
ssmm tag list kintone-api-token
ssmm tag remove kintone-api-token owner

# 全 app namespace のダッシュボード
ssmm dirs

# 重複検出 (app 間で同じキー、または同一値)
ssmm check --duplicates --values

# Parameter 移行 — 3 段階の安全手順 (SSM は soft-delete が無いので慎重に)
ssmm migrate /old-prefix/app /myteam/app                      # step 1: copy のみ
ssmm migrate /old-prefix/app /myteam/app --delete-old         # step 2: dry-run + backup dump
                                                              #   → /tmp/ssmm-migrate-backup-<ts>.json
ssmm migrate /old-prefix/app /myteam/app --delete-old --confirm  # step 3: 実削除
```

## 既存の sync unit を exec モードへ移行

既に sync モードで動作している unit (`ExecStartPre=ssmm sync ...` +
`EnvironmentFile=...env`) を exec モードに切り替えたい場合、手編集ではなく
`ssmm migrate-to-exec` で drop-in を生成します:

```bash
# dry-run (デフォルト): 提案 drop-in を stdout に出す
ssmm migrate-to-exec \
  --unit myapp.service \
  --app myapp \
  --exec-cmd "/usr/bin/uv run python app.py --mode prod" \
  --keep-env-file /etc/defaults/common \
  --pre-exec "/usr/bin/playwright install chromium"

# 実際に drop-in を書き込み + systemd reload
ssmm migrate-to-exec ... --apply
```

- `--exec-cmd` は SSM 注入後に実行するコマンド。`systemctl cat <unit>` の
  既存 `ExecStart=` 値をそのまま貼ってください。systemd の `show` / `cat`
  出力はバージョン間で差があり drop-in reset も絡むため、ssmm は敢えて
  自動パースしません。
- `--keep-env-file PATH` は SSM 由来ではない `EnvironmentFile=` エントリ
  (マシン共通の PATH 設定など) を保持します。それ以外は全てクリアされ、
  古い `.env` が読まれなくなります。
- `--pre-exec CMD` はクリア後に `ExecStartPre=` を再投入します。元の
  `ExecStartPre` に `ssmm sync` 以外の前処理 (playwright install、キャッシュ
  warm 等) が混ざっていた場合、残したいものだけを列挙してください。
- `--apply` で `<drop-in-dir>/exec-mode.conf` を書き込み、
  `systemctl [--user|--system] daemon-reload` を実行します。`--apply` なしは
  純粋な stdout dry-run。
- **revert はコマンド 1 つ**: `rm <drop-in> && systemctl daemon-reload`。
- sdtab 管理下の unit でも動作確認済。生成 drop-in は sdtab 自身の
  `<unit>.d/v2-syslog-identifier.conf` スタイルの drop-in と共存します。
  後で `sdtab upgrade` を走らせる場合、`exec-mode.conf` が残るか確認してください。
  残らない場合は issue 報告をお願いします。

## グリーンフィールドアプリを 1 コマンドで onboard

`ssmm onboard` は、まだ SSM に入っていないアプリ向けに `put --env <file>` と
`migrate-to-exec` を 1 コマンドに統合したものです。`.env` を読み、各キーを
put し、systemd drop-in を生成し、`daemon-reload` までを一気通貫で実行します。

```bash
# dry-run (デフォルト): put 計画 + drop-in プレビューを出力、ファイル書き込みなし
ssmm onboard \
  --unit myapp.service \
  --app myapp \
  --env ./myapp.env \
  --exec-cmd "/usr/bin/uv run python app.py --mode prod" \
  --keep-env-file /etc/defaults/common \
  --pre-exec "/usr/bin/playwright install chromium"

# 実際に put + drop-in 書き込み + daemon-reload
ssmm onboard ... --apply
```

- **デフォルトは既存キーがあれば fail**。`onboard` を 2 回実行しても、
  その間にローテーションした secret を silently 上書きすることはありません。
  `--overwrite` で replace-existing セマンティクスに opt-in 可能。
  `--overwrite` 時の dry-run も衝突キーを `# WILL OVERWRITE` ヘッダー配下に
  列挙するので、破壊的意図が見える化されます。
- `.env` の空値 (`FOO=`) は事前にフィルタされ (`put` の挙動と一致)、
  末尾の `FOO=` が spurious な "would overwrite" ノイズを起こしません。
- 値は dry-run 出力に一切登場しません (名前と `len=N` のみ)。
  snapshot test でこのプロパティを pin しています。
- **apply 途中で失敗した場合** — SSM put は成功したが `daemon-reload` が
  失敗した — エラーメッセージが `ssmm delete <app> -r` で SSM 側を revert する
  手順を示します。書き込まれた drop-in はエラー内に表示される path を
  `rm <path>` で削除できます。
- **既に SSM にあるアプリなら `migrate-to-exec` を使ってください**。モード
  切り替えのみに特化しています。`onboard` の default-fail ガードが二重 put を
  止めます。

## systemd 統合

脅威モデルに応じて 2 形態から選べます。どちらも user-scoped systemd unit
(下の例) にもシステムワイドにも使えます。

```ini
# (a) sync モード — アプリの横に mode 0600 の .env を配置してから起動。
# EnvironmentFile= を読む既存アプリはそのまま動く。
# ~/.config/systemd/user/myapp.service
[Service]
Environment=SSMM_PREFIX_ROOT=/myteam
ExecStartPre=/home/you/.cargo/bin/ssmm sync --app myapp --out /opt/myapp/.env
EnvironmentFile=/opt/myapp/.env
ExecStart=/opt/myapp/run.sh
```

```ini
# (b) exec モード — ディスクに .env なし。ssmm exec が自身をアプリに置換し、
# SSM 値を environ で渡す。平文ファイルを disk に残せないとき向け。
[Service]
Environment=SSMM_PREFIX_ROOT=/myteam
ExecStart=/home/you/.cargo/bin/ssmm exec --app myapp -- /opt/myapp/run.sh
```

注意:

- `ssmm sync` は冪等: 生成内容が既存ファイルと byte-for-byte 一致すれば
  no-op (`ssmm: no change`)。
- `ssmm exec` は `execvp` を使うので systemd は子プロセスを直接認識します —
  `Type=simple` セマンティクス、シグナル配送、MainPID、journal 出力全てが
  systemd がアプリを直接起動したかのように動作します。supervisor ラッパー
  不要。
- exec モードでは必ず子コマンドの前に `--` を置いてください。子の
  (`--port`, `-H` 等の) フラグが ssmm に食われないようにするためです。

## 共有 namespace とタグオーバーレイ

複数アプリで共有する値には `ssmm` では 2 つの表現があります:

```bash
# 跨アプリ値を /<prefix>/shared/* に直接配置
ssmm put --app shared --env /path/shared.env

# または既存の per-app parameter に shared タグを付ける
ssmm tag add kintone-api-token shared=true

# sync は自動で /<prefix>/shared/* をオーバーレイ (`--no-shared` で無効化)
# タグマッチしたものは --include-tag で取り込み
ssmm sync --include-tag shared=true
```

同じキー名が複数レイヤーに現れたときの優先順位:
**app > include-tag > shared**。衝突は stderr にログ出力されます。

## 自動検出

`--app` を省略した場合、`ssmm` は現在のディレクトリ名を採用します:

- `/home/you/services/my_api/` → `my-api` (snake_case → dash-case)
- `/home/you/services/billing-svc/` → `billing-svc`

いつでも `--app <name>` で上書き可能。

## Path 値とポータビリティ

SSM は parameter 値を opaque なバイト列として保存します。`ssmm` は `~` の
ようなシェル省略記法を入出力時に展開しません。値がファイルシステム path の
場合、`$HOME` 相対形を採用し、consumer アプリ側で実行時に展開してください:

```
# SSM parameter (portable)
GOOGLE_SERVICE_ACCOUNT_KEY_PATH=~/.credentials/service-account.json
```

```python
# Python — アプリ側
import os
path = os.path.expanduser(os.getenv("GOOGLE_SERVICE_ACCOUNT_KEY_PATH") or "")
```

なぜ重要か: 絶対 path (例: `/home/ec2-user/...`) を SSM に書くと、その 1 ホストでは
動くが別 `$HOME` のローカル開発環境で silently 壊れます。`~` + `expanduser` なら
1 つの SSM 値が全環境で動きます。Path 系の env var 全般に同じ原則が当てはまります
— portable に保存し、read 時に展開してください。

## 並列度とスロットリング

SSM の `PutParameter` はアカウント単位で低めの TPS (standard parameter で
~3/s) を持ちます。`ssmm` は AWS SDK の adaptive retry (`max_attempts=10`) と
合わせて `--write-concurrency=3` をデフォルトにしており、手動バックオフなしで
バルク投入が完了します。read は `--read-concurrency=10` がデフォルト。どちらも
呼び出しごとに調整可能:

```bash
ssmm --write-concurrency 1 put --env .env     # より厳しいスロットリング回避
ssmm --read-concurrency 20 list --all          # limit が緩いアカウントで高速化
```

## Advanced tier と custom KMS キー

デフォルトが合わないケース向けの opt-in スイッチが 2 つ:

```bash
# Advanced tier: parameter ごとの上限を 4KB → 8KB に拡張。
# 証明書、PEM キー、大きな JSON blob に必要。
# Advanced 1 parameter あたり月 $0.05 (Standard は無料)。
ssmm --advanced put --env .env

# Custom KMS キー: デフォルトの AWS マネージドキー (`alias/aws/ssm`) の代わりに
# チームスコープの CMK を使用。decrypt 権限を key policy で
# IAM principal のサブセットに絞りたいときに有用。
ssmm --kms-key-id alias/myteam-ssm put --env .env
```

注意:

- `--kms-key-id` は **新規作成** SecureString parameter にのみ影響します。
  既存 parameter は元のキーを保持します (AWS は in-place re-key を許可しない —
  ローテートが必要なら削除して再作成)。
- 4KB を超える値を migrate するときは `ssmm migrate` にも `--advanced` を
  渡してください。さもないとコピー時に `ValidationException` で失敗します。
- Tier のダウングレード (Advanced → Standard) は SSM が非対応。一度
  Advanced になると削除まで Advanced のままです。

## セキュリティモデル

`ssmm` は **堅牢な secret manager ではありません**。SSM 上の `.env` 互換
レイヤーに過ぎません。脅威モデルに応じて判断し、適切な配送モード
(`sync` か `exec`) を選んでください。

### `ssmm sync` が実際にやること

`ssmm sync` は `GetParametersByPath` を `--with-decryption` 付きで呼び、
結果の `KEY=VALUE` 行を出力 path に書き、`chmod 0600` します。復号された
SecureString 値は以下に存在します:

1. `ssmm sync` を実行しているホストのメモリ上
2. ディスク上のファイル (mode 0600、所有者のみ読み取り可)
3. `systemd` が `EnvironmentFile=` を読み込んだ後のターゲットプロセスの
   environ (同 UID / root から `/proc/<pid>/environ` で読める)

### `ssmm exec` が実際にやること

`ssmm exec` は同じ `GetParametersByPath` + 復号を行いますが、その後
`execvp` で子コマンドに置換し、SSM 値を継承 environ に追加します。復号された
SecureString 値は以下に存在します:

1. SSM fetch 中のホストのメモリ上
2. 子プロセスの environ (同 UID / root から `/proc/<pid>/environ` で読める)

つまり **`sync` の step 2 (ディスク上のファイル) が `exec` には存在しない** —
これが両モードの主要な違いです。

### どちらのモードでも防げること

- 平文 `.env` の git へのうっかりコミット (SSM が source of truth)
- SSM 読み取り権限はあるがホストログイン権限のない同僚
- ホスト間のドリフト (手でコピーした `.env` に対する中央管理)

### どちらのモードでも防げないこと

- **同 UID プロセスのスヌーピング**: `/proc/<pid>/environ` は同 UID プロセス
  (と root) から読み取り可能。アプリ起動後、両モードとも値を露出します。
- **ホスト侵害**: ファイルシステム読み取り権限を持つ攻撃者はプロセス
  environ を見えます。`sync` ではさらに平文 `.env` も見えます。
- **systemd journal / CloudWatch ログ経由の漏洩**: `ssmm` は parameter の
  **値が error メッセージや log 出力に一切現れない** よう設計されています
  (parameter 名 / 件数 / 長さ / SHA-256 ハッシュのみ)。もし stderr や
  journalctl に値が漏れる経路を見つけたら issue を立ててください — バグ扱い
  です。CloudWatch / fluent-bit / Datadog log への統合時は、独自ラッパーも
  この規律を守っているか確認してください。

### `exec` が `sync` に対して追加で防げること

- **バックアップ漏洩**: 平文ファイルが無いので `/opt/myapp/` のバックアップが
  secret を漏らさない (バックアップがプロセスメモリや `/proc` まで取る稀な
  ケースは除く)。
- **同一ホストの別 UID からのファイル読み取り**: sync の `.env` は 0600 だが
  ファイルであることには変わりない。`exec` モードの値はプロセスの environ
  にしか存在せず、カーネルのプロセス分離で保護される。

### 脅威モデルがいずれのモードよりも厳しい場合

同 UID environ 露出すら避けたいなら次のツール群を検討:

- **HashiCorp Vault + agent** — 短命リース、監査ログ
- **SOPS + age/KMS** — 暗号化済みファイル、アプリ内でのみ復号
- **ランタイム secret broker** (AWS Secrets Manager SDK をアプリ内から呼び、
  ローテート値、短命 in-memory 保持にスコープを絞る)

## 類似ツール

以下は詳細ベンチマークしておらず、方向付けとして扱ってください。権威ある
比較ではありません。positioning が違うと感じた場合は Issue / PR 歓迎:

- **[chamber](https://github.com/segmentio/chamber)** — SSM ベースの
  exec-time env 注入。`ssmm exec` が `ssmm` 内の対応モードです (仕組みは
  同じ: decrypt + `execvp` + env オーバーレイ)。`ssmm` は 3 セグメント
  prefix 規約 `/<team>/<app>/<key>`、shared namespace、タグオーバーレイを
  追加で提供し、chamber にはこれらのモデルはありません。
- **[aws-vault](https://github.com/99designs/aws-vault)** — exec-time の
  AWS 認証情報注入。問題領域は異なる (IAM credentials vs アプリ secret) が
  「ディスクに平文を置かない」哲学は共通。
- **dotenv-vault** — ホスト型 `.env.vault` フォーマット。AWS ネイティブ
  ではない。
- **HashiCorp Vault** — フル secret ライフサイクル管理 (リース、ローテーション、
  監査)。別ティアのツール。

### ssmm を選ぶとき

1. チームが **複数のサービス** で secret namespace を共有しており、チーム境界
   で IAM ポリシースコープ付きの prefix 規約 (`/<team>/<app>/<key>`) が欲しい。
2. **両方** 必要: `.env` ファイル生成 (レガシーな `EnvironmentFile=`
   consumer 向け) と chamber スタイルの exec-time 注入を 1 ツール・1 IAM
   ポリシー・1 メンタルモデルで。
3. CWD によるアプリ名自動検出、跨アプリ値の shared namespace、タグベースの
   オーバーレイが最初から欲しい。

### 他のツールを選ぶとき

- Secret ローテーション / リース / 監査ログが必要 → HashiCorp Vault。
- AWS 上でない → SOPS + age、dotenv-vault、または Doppler。
- アプリがランタイム (プロセス起動時ではなく) で secret を取得する必要がある →
  AWS Secrets Manager / Parameter Store SDK をアプリから直接呼び出し。

## Claude Code skill (bundled)

このリポジトリには [Claude Code](https://docs.claude.com/en/docs/agents-and-tools/claude-code/overview)
用の skill が `.claude/skills/ssmm/SKILL.md` に同梱されており、典型的な
`put → sync → systemd` ワークフロー、移行パターン、SecureString ヒュー
リスティックの上書きスイッチなどをカバーしています。Claude Code を使うなら
symlink か copy で取り込み可能:

```bash
# 方法 1: symlink (git pull で更新が追随)
ln -s $(pwd)/.claude/skills/ssmm ~/.claude/skills/ssmm

# 方法 2: copy (clone 時点で固定)
cp -r .claude/skills/ssmm ~/.claude/skills/ssmm
```

以後、Claude Code セッションで `/ssmm` を叩くとワークフローが展開されます。

## ライセンス

MIT。[LICENSE](./LICENSE) を参照。
