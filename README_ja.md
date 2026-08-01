# codehelion

[![CI](https://github.com/libraz/codehelion/actions/workflows/ci.yml/badge.svg)](https://github.com/libraz/codehelion/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/codehelion.svg)](https://crates.io/crates/codehelion)
[![codecov](https://codecov.io/gh/libraz/codehelion/branch/main/graph/badge.svg)](https://codecov.io/gh/libraz/codehelion)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](https://www.rust-lang.org)

Rust / C / C++ のコードベースを対象に重複ロジックを検出する、完全ローカル実行の
コマンドラインツールです。ソースコードや解析結果を外部に送信せず、
ネットワークアクセスを必要とせず、既定では解析対象のコードを実行しません。

ビルド不要の解析モードを 2 つと、任意のコンパイラ補助モードを提供します。**Fast** はトークンレベルの
Type-1（完全一致）・Type-2（識別子リネーム・リテラル変更）検出で、数十万行を数秒、
数百万行を数分でスキャンします。**Structural** は構文構造ベースの Type-3 検出を加え、文の追加・削除・
変更を伴うクローンを検出したうえで、判定根拠となった次元別 similarity を報告します。
**Semantic** は別途導入する Rust / Clang helper を使い、main CLI へ compiler API をリンクせずに
コンパイラが解決した型・名前の情報を取り込みます。任意の `artifact` コマンドは WASM、ELF、Mach-O、
PE/COFF、静的アーカイブをローカルで読み取り、観測済みサイズ、重複したコード・データ、retained size、
ソース位置の根拠を報告します。成果物をロードまたは実行することはありません。

## 特長

- **ビルド不要のスキャン** — エラー耐性のある lexer が Rust / C / C++ ソースを
  直接処理します。コンパイラ・ビルドシステム・`compile_commands.json` は不要です。
- **任意のコンパイラ補助スキャン** — Semantic モードは Rust / Clang helper を別プロセスで実行し、
  答えられなかったファイルと理由も記録します。既定ではプロジェクトの build script など実行可能な
  build input を動かさず、許可する実行分類は CLI で個別に明示します。
- **安定した finding ID** — 検出結果は行番号ではなく内容 fingerprint で識別され、
  無関係な編集で ID が変わりません。
- **単一スコアではなく根拠** — gapped クローンは lexical / structural / control-flow /
  type / API の similarity を個別に報告します。そのモードで測定できない次元は推測せず、
  測定なしとして報告します。
- **ローカルの現行スキャン保存** — 最新のスキャンは SQLite データベースへ保存されます。
  text / JSON / SARIF レポートはその現行スナップショットの export です。スキャンは
  直前のスナップショットを置き換えるため、遡れる履歴もスキャン間の lineage も
  ありません。あるスキャンを次のスキャンの比較対象として持ち越すのは baseline の役割です。
- **ローカルの成果物検査** — `artifact analyze` と `artifact compare` は対応するバイナリ形式を
  実行せずに読み取ります。デバッグ情報は ELF build ID、Mach-O UUID、または PE CodeView/PDB identity が
  一致した場合にだけ受け入れます。
- **分離された優先度指標** — clone confidence・maintenance risk・refactoring difficulty
  を並べて報告し、不透明な単一スコアで順序を決めません。各指標は導出に使った
  入力値とともに表示されます。
- **決定的な出力** — 同一入力からはバイト単位で一致するレポートが得られます。
- **可視化された上限** — 発火したリソース上限（ファイルサイズ・parse timeout・
  候補 budget）はすべてレポートに計上され、黙って適用されることはありません。
  候補 budget が探索を打ち切るほど大きなツリーでは、**未検査のまま残したペア数を
  レポートが明示します** — 部分的な答えを完全な答えとして提示しません。
- **保守性の指標であってサイズの指標ではない** — 検出結果が示すのは読み手が同期を
  取り続ける必要のあるコードであり、コンパイラが出力するバイト数ではありません。
  最適化器はソース上で重複したままのコードを日常的に畳むため、報告されたクローンを
  解消しても成果物が小さくなるとは限りません。

## インストール

```sh
# チェックアウトから（crates.io / PyPI / Homebrew での配布は準備中）:
cargo install --path crates/codehelion-cli
```

生成されるのは自己完結の単一バイナリで、SQLite は同梱されています。

Semantic スキャンでは、解析したい言語ごとの helper も必要です。helper を `PATH` に導入し、
`doctor` で protocol と compiler の利用可否を確認してください。

```sh
cargo install --path crates/codehelion-backend-rust
cargo install --path crates/codehelion-backend-clang # システムの libclang も必要
codehelion doctor
```

## 使い方

```sh
codehelion scan               # カレントディレクトリをスキャンし text レポート
codehelion scan --mode structural           # gapped（Type-3）クローンも検出
codehelion scan --mode semantic             # コンパイラが解決した型で比較（helper が必要）
codehelion scan --format json --output report.json path/to/repo
codehelion scan --format sarif --output report.sarif   # SARIF 2.1.0 ログ
codehelion scan --verbose     # 全クローングループと全メンバーを列挙
codehelion scan --untrusted   # 素性の分からないツリーを低い上限で読む
codehelion explain <ID>       # ローカルデータベースから finding を表示
codehelion baseline           # 既知 finding の baseline を管理
codehelion cache status       # ローカルデータベースの場所とサイズ
codehelion config init        # コメント付き codehelion.toml テンプレートを生成
codehelion doctor             # 利用可能な解析コンポーネントを表示
codehelion artifact analyze path/to/binary
codehelion artifact compare before/binary after/binary
```

成果物検査はローカルのバイト列を parse するだけで、対象プログラムを実行しません。既定では
512 MiB を超える入力を拒否し、30 秒の期限を持つ worker で parse します。意図的に調整する
場合は `--max-bytes` と `--timeout-seconds` を指定できます。Linux では
`--max-memory-bytes <bytes>` により worker の仮想メモリ上限も強制します。ほかの OS では
このオプションを黙って無視せず、エラーとして返します。

検出結果はクローングループにまとめられ、グループとメンバーそれぞれが安定 ID を
持ちます。この ID で suppression・baseline 登録・`explain` での後日参照ができます。

判断済みの finding は `codehelion baseline create` で凍結でき、以降のスキャンは
それを隠します。データベースが保持するスキャンは常に 1 件なので、前後比較の
手段も baseline です。

```sh
codehelion scan                       # ツリーを読む
codehelion baseline create .          # 起点を記録する
# ... 重複を減らす ...
codehelion scan --baseline codehelion-baseline.json --baseline-mode compare
```

`compare` は何も隠しません。各グループを「baseline が凍結したもの」と「そうで
ないもの」に分けて報告し、消えたトークン量と現れたトークン量を並べて出します。
この 2 つが揃っていないと、大きな重複 4 件を解消して小さな重複 20 件が現れた
状態が退行に見えてしまいます。また重複の解消はその周辺のコードも書き換えるため、
組み替えの結果として現れるグループは新しい ID を持ちます。直前までエントリが
あった場所に立っているグループは、誰かが足した重複としてではなく、そこに立って
いるものとして報告されます。

BuildVariant または detector version が異なる場合は、履歴を引き継がず現行
スキャンから baseline を作り直します。

## 設定

`codehelion scan` はスキャンルートの `codehelion.toml`（任意）を読み込みます。
`codehelion config init` で全項目コメント付きのテンプレートを生成できます。主な項目:

```toml
# min-clone-tokens = 20             # 報告する最小クローン長（トークン数）
# literal-normalization = "full"    # "preserve" / "category" / "full"
# database = ".codehelion/audit.db" # ローカルデータベースの場所

[languages]
# headers = "detect"                # 拡張子 ".h" を読む文法。"detect" / "c" / "cpp"

[priority]                          # 整数シェアとして読む
# maintenance-risk = 2              # 設定できるのは合成のみ。重複が何を要求するかは
# refactoring-ease = 1              # コード側の性質であり設定で変えない

[suppression]
# paths = []                        # 隠すパス glob
# vendored-paths = [...]            # 自分では書かない vendored ツリー。既定で
                                    # 隠す。[] にするか --include-vendored で解除
# symbols = []                      # 所属ユニット名に対する glob
# clone-ids = []                    # 安定クローン ID（hex、前方一致可）
# generated-markers = ["@generated", "do not edit", "automatically generated"]
                                    # 生成物を示すバナー。大文字小文字は無視。
                                    # 設定すると既定値を置き換える

[limits]                            # リソース上限。発火時は必ずレポートに計上
# max-file-bytes = 2097152
# parse-timeout-ms = 10000
# helper-timeout-ms = 300000       # Semantic helper 応答の期限
# posting-cap = 64                  # 未設定ならモードごとの既定値のまま
# pair-budget = 1000000             # ペア生成 pass ごと。pass 間で共有しない
# max-component = 1024
```

`.h` は C と C++ が共有する唯一の拡張子で、どちらの文法で読むかがその中身の
見え方を決めます。C++ ヘッダを C として読むと、エラー回復によって何も宣言
しない形へ崩れ、本来の重複を隠す一方でクラス本体どうしの重複を捏造します。
`detect` は拡張子が曖昧でないファイルを数えて多数派に従います。数えるものが
無い木——ヘッダのみのライブラリ——では、ヘッダ自身を読んで C++ にしか書けない
綴りを探し、1 つでも見つかればその run 全体が C++ になります。この選択は
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
