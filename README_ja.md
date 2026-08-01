# codehelion

[![CI](https://github.com/libraz/codehelion/actions/workflows/ci.yml/badge.svg)](https://github.com/libraz/codehelion/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/codehelion-cli.svg)](https://crates.io/crates/codehelion-cli)
[![codecov](https://codecov.io/gh/libraz/codehelion/branch/main/graph/badge.svg)](https://codecov.io/gh/libraz/codehelion)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](https://www.rust-lang.org)

Rust / C / C++ のコードベースを対象に重複ロジックを検出する、完全ローカル実行の
コマンドラインツールです。ソースコードや解析結果を外部に送信せず、
ネットワークアクセスを必要とせず、既定では解析対象のコードを実行しません。

ビルド不要の解析モードを 2 つと、任意のコンパイラ補助モードを提供します。**Fast** はトークンレベルの
Type-1（完全一致）・Type-2（識別子リネーム・リテラル変更）検出で、数十万行を数秒、
数百万行を数分でスキャンします。比較前にコメントと空白を除くため、コメントだけの編集で本来同一のコードが
別の finding になることはありません。**Structural** は構文構造ベースの Type-3 検出を加え、文の追加・削除・
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

`artifact analyze --debug-file companion` は source scan なしでも native debug companion を
検査できます。source-artifact correlation を要求する場合にだけ `--source-run` と
`--build-variant` を追加します。
- **分離された優先度指標** — clone confidence・maintenance risk・refactoring difficulty
  を並べて報告し、不透明な単一スコアで順序を決めません。各指標は導出に使った
  入力値とともに表示されます。
- **決定的な検出結果** — 同一入力からは同じ finding ID とグループ順序が得られます。
  timestamp やローカル path のような run metadata は、個々の実行を表すため意図的に変わります。
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

CLI と Semantic 以外のコンポーネントには Rust 1.85 以降が必要です。任意の
Rust Semantic helper は別途 Rust 1.95 以降でのビルドを必要としますが、この高い
要件は CLI の MSRV を引き上げません。

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
codehelion report --run 1     # 記録済みスキャンを再描画
codehelion explain <ID>       # ローカルデータベースから finding を表示
codehelion explain <ID> --format json
codehelion baseline create    # 最新の finding を baseline として固定
codehelion cache status       # ローカルデータベースの場所とサイズ
codehelion cache clear --force # ローカル監査データベースを恒久的に削除
codehelion config init        # コメント付き codehelion.toml テンプレートを生成
codehelion config show        # 有効な設定を表示
codehelion doctor             # 利用可能な解析コンポーネントを表示
codehelion artifact analyze path/to/binary
codehelion artifact report --analysis 1
codehelion artifact compare before/binary after/binary
codehelion artifact calibration --source-run 1
```

artifact command に `--build-variant manifest.json` を渡すと、build variant の
identity には正規化した JSON 値を使います。空白や object member の順序は identity を
変えません。

主な scan の制御項目:

- `--config <file>` と `--db <path>` は設定ファイルとローカルデータベースを選びます。
- `--jobs <n>` は frontend の read/lex worker 数を指定します（host parallelism の 4 倍まで）。clone grouping と report rendering は serial です。`--no-ignore` は無視対象のファイルも読みます。
- `--baseline <file>` は判断済みの finding と比較し、`--show-suppressed` は text 出力に隠した finding も含めます。
- `--include-trivial` は Structural / Semantic mode で predicate family を計測済み priority に戻します。
- `--fail-on-findings` は visible finding が残ると exit code 3 を返します。
- `--compare-build-variants` と `--compare-languages` は独立した Semantic comparison を要求し、通常の scan partition を混ぜません。
- `cache clear --force` はローカル監査データベースを恒久的に削除します。常に明示的な確認 flag が必要です。

### Exit status

- `0`: コマンドは成功しました。
- `1`: 実行上のエラーにより完了できませんでした。
- `2`: command-line の指定が不正です。
- `3`: `scan --fail-on-findings` が 1 件以上の visible finding を検出しました。

成果物検査はローカルのバイト列を parse するだけで、対象プログラムを実行しません。既定では
512 MiB を超える入力を拒否し、30 秒の期限を持つ worker で parse します。意図的に調整する
場合は `--max-bytes` と `--timeout-seconds` を指定できます。Linux では
`--max-memory-bytes <bytes>` により worker の仮想メモリ上限も強制します。ほかの OS では
このオプションを黙って無視せず、エラーとして返します。
`artifact report` 用に保存する versioned IR には別途 64 MiB の上限があり、保存対象の詳細が
これを超える分析は partial な DB record を残さず失敗します。

検出結果はクローングループにまとめられ、グループとメンバーそれぞれが安定 ID を
持ちます。既定の text report は各 member を `[finding <ID>]` と表示するため、その
まま `codehelion explain <ID>` に渡せます。この ID で suppression・baseline 登録・
`explain` での後日参照ができます。

レポートは既定で合成された priority 順に並びます。priority は複数の指標を重み付け
して束ねた値なので、目の前の作業がそのうちのひとつの指標そのものである場合は、
その軸で直接並べ替えられます。

```sh
codehelion scan --sort duplicated-tokens    # 繰り返されているトークン量が多い順
codehelion scan --sort instances            # 複製された箇所が多い順
codehelion scan --sort identifier-jaccard   # 識別子の一致度が高い順
```

保守性を目的とする場合は、`--sort identifier-jaccard` に下限を付けるのが当たりを
引きやすい方法です。識別子がまだ一致している複製は、まだ誰も分岐させていない複製
であり、共通関数ひとつで置き換えられる余地が残っています。

```sh
codehelion scan --mode structural --sort identifier-jaccard --min-identifier-jaccard 0.7
```

この下限は同じ検出結果に対する見え方の指定です。テキスト表示の対象を決めるだけで、
集計値・エクスポート・記録内容のいずれも変えません。識別子の一致度はユニット全体
に対して測るため、fragment を報告する実行では比較する値がなく、その分を「表示しな
かった件数」として明示します。

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
# jobs = 4                           # frontend read/lex worker 数（host parallelism の 4 倍まで）。grouping/reporting は serial

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
# clone-ids = []                    # 安定クローン ID（hex、前方一致は 8 文字以上）
# generated-markers = ["@generated", "do not edit", "automatically generated", "auto-generated", "autogenerated"]
                                    # 生成物を示すバナー。大文字小文字は無視。
                                    # 設定すると既定値を置き換える
# split-pairs = "rank-down"        # 完全なクローングループに入らない検証済み
                                    # ペア。完全なグループより後ろに表示
# width-family = "hide"            # 整数幅だけが違う同形の関数群。統合できる
                                    # 場合は "report" にする

[limits]                            # リソース上限。発火時は必ずレポートに計上
# max-file-bytes = 2097152
# parse-timeout-ms = 10000
# helper-timeout-ms = 300000       # Semantic helper 応答の期限
# posting-cap = 64                  # 未設定ならモードごとの既定値のまま
# pair-budget = 1000000             # ペア生成 pass ごと。pass 間で共有しない
# max-component = 1024
```

split-pairs は、同じ完全なクローングループに入らない検証済みペアを制御します。
既定では非表示にせず、完全なグループより後ろに表示します。width-family は整数幅
だけが違う関数群を制御し、既定では隠します。macro・generic・template でその関数群を
一度だけ書けるなら、"report" に設定してください。これらの分類は Structural と
Semantic scan で適用され、Fast scan では利用できないことを明示します。

各 scan は既定で `.codehelion/audit.db` に永続的なローカル監査データベースを作ります。置き場所は scan root を含む Git リポジトリの直下で、サブディレクトリを scan したときに新しいデータベースを作らずリポジトリのものを使い続けるためです。どのリポジトリにも属さない scan root は自分の下に持ちます。場所は `--db <path>` で上書きできます。リポジトリの `.gitignore` に `.codehelion/` を追加してください。このデータベースは捨ててよい build cache ではありません。

一方 `codehelion.toml` は scan root 自身からしか読まず、親ディレクトリから継承することはありません。scan はどの設定に従ったかとその出所を報告するものであり、読んでいる木より上にある誰も指定していないファイルはそれに当たらないからです。

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
した `clippy`（`unsafe` は禁止）、依存関係の advisory・ban・license を確認する
`cargo-deny`、scan path のプロセス起動と network socket を禁止する `clippy.toml`、対象コードと
同時に書くテスト、`make check` 一式を実行する pre-commit フック。

## ディレクトリ構成

```text
crates/
  codehelion-artifact/        共通の artifact 解析・correlation
  codehelion-artifact-archive/ archive member の検出
  codehelion-artifact-elf/    ELF parser
  codehelion-artifact-macho/  Mach-O parser
  codehelion-artifact-pe/     PE/COFF parser
  codehelion-artifact-wasm/   WebAssembly parser
  codehelion-backend-clang/   分離実行する C/C++ compiler helper
  codehelion-backend-rust/    分離実行する Rust compiler helper
  codehelion-cli/            コマンドラインインターフェース・設定・レポーター
  codehelion-core/           discovery・クローンエンジン・fingerprint・doctor
  codehelion-eval/           精度評価ハーネス・内部ツール
  codehelion-fixtures/       テスト用 fixture tree
  codehelion-frontend-rust/  ビルド不要の Rust lexer frontend
  codehelion-frontend-c/     ビルド不要の C lexer frontend
  codehelion-frontend-cpp/   ビルド不要の C++ lexer frontend
  codehelion-helper/         helper protocol・client
  codehelion-helper-conformance/ helper protocol の conformance test
  codehelion-store/          SQLite 監査ストア（スナップショット・baseline）
corpus/                      ラベル付き評価 corpus（corpus/README.md 参照）
```

## 制限

欠落や編集のあるコピーは検出しにくくなります。codehelion はミラーの整合性検査ツールではありません。Structural detector は、候補にならないほど差異が大きい場合、ほかの点では似ているミラーを見逃すことがあります。

## ライセンス

[Apache License, Version 2.0](LICENSE) で提供します。
