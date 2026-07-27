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
  `audit` は前回スキャンから各グループがどうなったかを報告します。
- **分離された優先度指標** — clone confidence・maintenance risk・refactoring difficulty
  を並べて報告し、不透明な単一スコアで順序を決めません。各指標は導出に使った
  入力値とともに表示されます。
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
codehelion audit              # 前回から重複がどうなったかを報告
codehelion explain <ID>       # 監査データベースから finding を表示
codehelion baseline           # 既知 finding の baseline を管理
codehelion cache status       # 監査データベースの場所とサイズ
codehelion config init        # コメント付き codehelion.toml テンプレートを生成
codehelion doctor             # 利用可能な解析コンポーネントを表示
```

検出結果はクローングループにまとめられ、グループとメンバーそれぞれが安定 ID を
持ちます。この ID で suppression・baseline 登録・`explain` での後日参照ができます。

`codehelion audit` は記録済みの 2 つのスキャンを比較し、各グループが新規なのか、
変化していないのか、解消されたのか、出現数が増減したのか、移動したのか、内容が
乖離したのか、クローン種別が変わったのかを報告します。グループは行番号ではなく
内容で対応付けるため、ファイルの再インデントやクローン直上へのコメント追加で
履歴が途切れることはありません。

判断済みの finding は `codehelion baseline create` で凍結でき、以降のスキャンは
その後に現れたものだけを報告します。リリースで ID の作り方そのものが変わると
（リテラル畳み込み方式の変更、正規化規則の更新など）記録済みの ID はすべて動き、
何も一致しなくなった baseline は正常に抑止できた baseline と見分けがつきません。
そのためこの種の変更は黙って適用せず報告し、`codehelion baseline migrate` が
凍結済みの判断と履歴を新しい ID の上へ書き換えます。引き継げなかった項目は
破棄せず 1 件ずつ名指しします。読む順序だけを変える変更では ID は 1 つも動かず、
利用者側のコストはゼロです。

## 設定

`codehelion scan` はスキャンルートの `codehelion.toml`（任意）を読み込みます。
`codehelion config init` で全項目コメント付きのテンプレートを生成できます。主な項目:

```toml
# min-clone-tokens = 20             # 報告する最小クローン長（トークン数）
# literal-normalization = "full"    # "preserve" / "category" / "full"
# database = ".codehelion/audit.db" # 監査データベースの場所

[languages]
# headers = "detect"                # 拡張子 ".h" を読む文法。"detect" / "c" / "cpp"

[priority]                          # 整数シェアとして読む
# maintenance-risk = 2              # 設定できるのは合成のみ。重複が何を要求するかは
# refactoring-ease = 1              # コード側の性質であり設定で変えない

[suppression]
# paths = []                        # 隠すパス glob。vendor 配下はここへ
# symbols = []                      # 所属ユニット名に対する glob
# clone-ids = []                    # 安定クローン ID（hex、前方一致可）
# generated-markers = ["@generated", "DO NOT EDIT"]

[limits]                            # リソース上限。発火時は必ずレポートに計上
# max-file-bytes = 2097152
# parse-timeout-ms = 10000
# posting-cap = 64                  # 未設定ならモードごとの既定値のまま
# pair-budget = 1000000             # ペア生成 pass ごと。pass 間で共有しない
# max-component = 1024
```

`.h` は C と C++ が共有する唯一の拡張子で、どちらの文法で読むかがその中身の
見え方を決めます。C++ ヘッダを C として読むと、エラー回復によって何も宣言
しない形へ崩れ、本来の重複を隠す一方でクラス本体どうしの重複を捏造します。
`detect` は拡張子が曖昧でないファイルを数えて多数派に従います。この選択は
run の build variant に含まれるため、異なる文法で読んだ結果どうしが比較され
ることはありません。

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
