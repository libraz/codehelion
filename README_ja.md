# codehelion

[![CI](https://github.com/libraz/codehelion/actions/workflows/ci.yml/badge.svg)](https://github.com/libraz/codehelion/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/codehelion.svg)](https://crates.io/crates/codehelion)
[![codecov](https://codecov.io/gh/libraz/codehelion/branch/main/graph/badge.svg)](https://codecov.io/gh/libraz/codehelion)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](https://www.rust-lang.org)

Rust / C / C++ のコードベースを対象に重複ロジックを検出し、その変化を追跡する、
完全ローカル実行のコマンドラインツールです。ソースコードや解析結果を外部に送信せず、
ネットワークアクセスを必要とせず、解析対象のコードを実行することもありません。

現行リリースは **Fast** 解析モードを提供します。トークンレベルの Type-1（完全一致）
と Type-2（識別子リネーム・リテラル変更）クローン検出で、ビルド不要のまま数十万行を
数秒でスキャンします。Structural（Type-3）・Semantic モードと任意のコンパイル成果物
解析は後続リリースで追加します。

## 特長

- **ビルド不要のスキャン** — エラー耐性のある lexer が Rust / C / C++ ソースを
  直接処理します。コンパイラ・ビルドシステム・`compile_commands.json` は不要です。
- **安定した finding ID** — 検出結果は行番号ではなく内容 fingerprint で識別され、
  無関係な編集で監査履歴が揺れません。
- **ローカル監査履歴** — 各スキャンは SQLite データベースへスナップショットされます。
  JSON / text レポートは export であり、正本はデータベースです。
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
codehelion scan --format json --output report.json path/to/repo
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
# paths = []                        # レポートから隠す glob パターン
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
