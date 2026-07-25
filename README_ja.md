# codehelion

[![CI](https://github.com/libraz/codehelion/actions/workflows/ci.yml/badge.svg)](https://github.com/libraz/codehelion/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/codehelion.svg)](https://crates.io/crates/codehelion)
[![codecov](https://codecov.io/gh/libraz/codehelion/branch/main/graph/badge.svg)](https://codecov.io/gh/libraz/codehelion)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](https://www.rust-lang.org)

Rust / C / C++ のコードベースを対象に重複ロジックを検出し、その変化を追跡する、
完全ローカル実行のコマンドラインツールです。ソースコードや解析結果を外部に送信せず、
ネットワークアクセスを必要とせず、解析対象のコードを実行することもありません。

現行リリースはビルド不要の解析モードを 2 つ提供します。**Fast** はトークンレベルの
Type-1（完全一致）・Type-2（識別子リネーム・リテラル変更）検出で、数十万行を数秒で
スキャンします。**Structural** は構文構造ベースの Type-3 検出を加え、文の追加・削除・
変更を伴うクローンを検出したうえで、判定根拠となった次元別 similarity を報告します。
Semantic モードと任意のコンパイル成果物解析は後続リリースで追加します。

## 特長

- **ビルド不要のスキャン** — エラー耐性のある lexer が Rust / C / C++ ソースを
  直接処理します。コンパイラ・ビルドシステム・`compile_commands.json` は不要です。
- **安定した finding ID** — 検出結果は行番号ではなく内容 fingerprint で識別され、
  無関係な編集で監査履歴が揺れません。
- **単一スコアではなく根拠** — gapped クローンは lexical / structural / control-flow /
  type / API の similarity を個別に報告します。そのモードで測定できない次元は推測せず、
  測定なしとして報告します。
- **ローカル監査履歴** — 各スキャンは SQLite データベースへスナップショットされます。
  text / JSON / SARIF レポートは export であり、正本はデータベースです。
- **決定的な出力** — 同一入力からはバイト単位で一致するレポートが得られます。
- **可視化された上限** — 発火したリソース上限（ファイルサイズ・parse timeout・
  候補 budget）はすべてレポートに計上され、黙って適用されることはありません。

## インストール

```sh
# チェックアウトから（crates.io / PyPI / Homebrew での配布は準備中）:
cargo install --path crates/codehelion-cli
```

生成されるのは自己完結の単一バイナリで、SQLite は同梱されています。

## 使い方

```sh
codehelion scan               # カレントディレクトリをスキャンし text レポート
codehelion scan --mode structural           # gapped（Type-3）クローンも検出
codehelion scan --format json --output report.json path/to/repo
codehelion scan --format sarif --output report.sarif   # SARIF 2.1.0 ログ
codehelion scan --verbose     # 全クローングループと全メンバーを列挙
codehelion explain <ID>       # 監査データベースから finding を表示
codehelion baseline           # 既知 finding の baseline を管理
codehelion config init        # コメント付き codehelion.toml テンプレートを生成
codehelion doctor             # 利用可能な解析コンポーネントを表示
```

検出結果はクローングループにまとめられ、グループとメンバーそれぞれが安定 ID を
持ちます。この ID で suppression・baseline 登録・`explain` での後日参照ができます。

## 設定

`codehelion scan` はスキャンルートの `codehelion.toml`（任意）を読み込みます。
`codehelion config init` で全項目コメント付きのテンプレートを生成できます。主な項目:

```toml
# min-clone-tokens = 20             # 報告する最小クローン長（トークン数）
# literal-normalization = "full"    # "preserve" / "category" / "full"
# database = ".codehelion/audit.db" # 監査データベースの場所

[suppression]
# paths = []                        # レポートから隠すパス glob
# symbols = []                      # 所属ユニット名に対する glob
# clone-ids = []                    # 安定クローン ID（hex、前方一致可）
# generated-markers = ["@generated", "DO NOT EDIT"]

[limits]                            # リソース上限。発火時は必ずレポートに計上
# max-file-bytes = 2097152
# parse-timeout-ms = 10000
# posting-cap = 64
# pair-budget = 1000000
```

## 開発

よく使う操作は `Makefile` にまとめてあります（一覧は `make help`）。

```sh
make format        # 自動修正: clippy --fix + cargo fmt
make format-check  # フォーマット検証
make lint          # clippy を警告エラー扱いで実行
make test          # テスト実行
make check         # format-check + lint + test + doc
make audit         # cargo-deny（脆弱性・禁止クレート・ライセンス）
make coverage      # HTML カバレッジレポート（cargo-llvm-cov が必要）
make hooks         # pre-commit git フックを導入
```

ガードレール: 設定を固定した `rustfmt`、`pedantic` + `nursery` を警告エラー扱いに
した `clippy`（`unsafe` は禁止）、完全ローカル設計を機械的に強制するための
`cargo-deny` によるネットワーク系・プロセス起動系クレートの禁止、対象コードと
同時に書くテスト、`make check` 一式を実行する pre-commit フック。

## ディレクトリ構成

```text
crates/
  codehelion-cli/            コマンドラインインターフェース・設定・レポーター
  codehelion-core/           discovery・クローンエンジン・fingerprint・doctor
  codehelion-store/          SQLite 監査ストア（スナップショット・baseline）
  codehelion-frontend-rust/  ビルド不要の Rust lexer frontend
  codehelion-frontend-c/     ビルド不要の C lexer frontend
  codehelion-frontend-cpp/   ビルド不要の C++ lexer frontend
  codehelion-eval/           精度評価ハーネス（内部用）
corpus/                      ラベル付き評価 corpus（corpus/README.md 参照）
```

## ライセンス

[Apache License, Version 2.0](LICENSE) で提供します。
