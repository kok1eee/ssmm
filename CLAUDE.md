# ssmm — Claude Code notes

## プロジェクト概要

AWS SSM Parameter Store を team-scoped `.env` 同期の source of truth にする
Rust CLI。`sync` モード (systemd EnvironmentFile= 用に `.env` 再生成) と
`exec` モード (プロセス env に直注入、ディスクに残さない chamber 互換) の
2 方式を提供。`migrate-to-exec` / `onboard` で既存 / 新規 systemd unit を
exec モード drop-in に移行。

## sdtab 連携の推奨パターン (v0.7.0+)

**`--cwd-app`** を使う。`migrate-to-exec` / `onboard` に付けると:

- `WorkingDirectory=<CWD>` を drop-in に出力
- `ExecStart=` から `--app <app>` を省略 (ssmm 側で CWD basename 自動判定)

sdtab の table で `cmd:` 行が短くなり、同じアプリを mode 別に複数 unit 化
する際の app 名重複が消える。実行時の `$PWD` がそのまま
`WorkingDirectory=` に書かれるので **repo ディレクトリ内で実行すること**。

```bash
cd ~/amu-tazawa-scripts/hikken_schedule
ssmm migrate-to-exec \
  --unit sdtab-hikken-bashtv.service \
  --app hikken-schedule \
  --exec-cmd "<現行 ExecStart>" \
  --cwd-app --apply
```

## 設計判断の要点

- **値を stderr / ログに出さない**: 名前・長さ・SHA-256 prefix のみ。値が
  stderr に漏れる path はバグと見なす。
- **SecureString デフォルト**: 保守的。`_url` は safe list に入れない
  (URL は credentials を含みやすい)。
- **migrate は 3-step**: SSM に soft-delete が無いため、`copy → dry-run + backup →
  --confirm` の段階踏み。
- **Advanced tier / 独自 KMS key は opt-in**: `--advanced` / `--kms-key-id`。
  指定時のみ効く。
- **prefix は必須**: `SSMM_PREFIX_ROOT` or `--prefix`。default 撤廃済み
  (v0.3.0)。
- **`--app` は CWD basename から自動判定**: snake_case → dash-case 変換。
  明示指定は `--app <name>`。

## Release workflow

1. 実装 + test (`cargo test`, 全 test pass を確認)
2. `Cargo.toml` の `version` を bump (semver: feature add → minor,
   fix → patch, breaking change → major)
3. `.claude/skills/ssmm/SKILL.md` の関連セクションを更新
4. `README.md` の関連セクションを更新
5. commit (Conventional Commits、`feat:` / `fix:` / `docs:` / `refactor:`)
6. tag (`v<version>`)
7. `git push origin master && git push origin v<version>`
8. `gh release create v<version> --notes-file -` で Release notes
9. `cargo publish`
10. `cargo install --path . --force` で手元 binary も更新

## VCS

git のみ (jj colocate は任意)。commit author は `tazawa-masayoshi@kcgrp.jp`
(コミッター本人)。force push は owner 判断で (`kok1eee` アカウント)。

## Do / Don't

- **Do**: 値を扱うコードで新しい log を追加するときは、値自体が出ないか
  必ず確認 (SHA-256 / len / 名前だけ)。
- **Do**: `build_drop_in` の挙動を変更したら systemd.rs 側の unit test を
  更新し、かつ onboard.rs 側の snapshot も整合を確認。
- **Don't**: `--app` を required にする。CWD 自動判定が入口の UX を握る。
- **Don't**: `cargo install --path .` の `target/release` を drop-in の
  `ssmm_bin` に書く (`cargo clean` で消える)。デフォルトの
  `$HOME/.cargo/bin/ssmm` が stable install 先。
