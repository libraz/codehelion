# codehelion

[![CI](https://img.shields.io/github/actions/workflow/status/libraz/codehelion/ci.yml?branch=main&label=CI)](https://github.com/libraz/codehelion/actions)
[![crates.io](https://img.shields.io/crates/v/codehelion.svg)](https://crates.io/crates/codehelion)
[![codecov](https://codecov.io/gh/libraz/codehelion/branch/main/graph/badge.svg)](https://codecov.io/gh/libraz/codehelion)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](https://github.com/libraz/codehelion/blob/main/LICENSE)
[![Rust](https://img.shields.io/badge/Rust-1.85%2B-orange?logo=rust)](https://www.rust-lang.org)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey)](https://github.com/libraz/codehelion)

Rust / C / C++ の重複ロジックを検出し、スキャンをまたいで同じ重複を追い続けるツールです。

codehelion はソースを直接読みます。ビルドも compilation database もネットワークも要りません。完全一致・リネーム・欠落を伴うコピーを検出し、判定に使った複数の指標を並べて報告し、各 finding には無関係な編集では変わらない内容由来の識別子を付けます。一度判断した重複は判断済みのまま残り、数か月後のスキャンを前回のスキャンと突き合わせられます。

処理はすべて実行したマシンの中で完結します。ソースコードも解析結果も外部に送信せず、ネットワークへの依存を持たず、実行分類ごとの許可フラグを渡さないかぎり読み取ったコードを実行しません。

ビルド不要の解析モードが 2 つと、任意のコンパイラ補助モードが 1 つあります。**Fast** はトークンレベルの Type-1（完全一致）・Type-2（識別子のリネーム、リテラルの変更）検出です。比較前にコメントと空白を除くため、コメントだけの編集でひとつの finding が 2 つに割れることはありません。**Structural** は Type-3 検出、つまり文の追加・削除・変更を伴うコピーの検出を加え、判定根拠となった次元別の similarity を報告します。**Semantic** は別途導入する Rust / Clang helper を動かし、CLI に compiler API をリンクせずにコンパイラが解決した型と名前の情報を取り込みます。

codehelion は 1.0 前です。コマンドラインの形・レポート形式・データベースのレイアウトはリリース間で変わり得ます。

## レポートの見え方

codehelion 自身のツリーに対する Structural モードの実行結果です（ヘッダの数行は省いています）。

```text
codehelion scan · structural mode · ~/src/codehelion

 #1  0.62  type-1 ×2  188 tokens  f7f71e71
     ├─ ◆ crates/codehelion-cli/src/scan/structural/reporting.rs:698-719
     └─   crates/codehelion-cli/src/scan/structural/reporting.rs:802-823

 #2  0.59  type-1 ×2  128 tokens  814ddea4
     ├─ ◆ crates/codehelion-frontend-c/src/ir.rs:437-451        line_column
     └─   crates/codehelion-frontend-rust/src/ir.rs:379-393     line_column

 #3  0.59  type-1 ×2  115 tokens  e6b021f2
     ├─ ◆ crates/codehelion-core/src/engine/segment.rs:20-35    brace_pairs
     └─   crates/codehelion-frontend-rust/src/units.rs:66-81    match_braces

... and 760 more groups (--limit 0 lists every one)

968 groups (type-1 71, type-2 126, type-3 771) · 205 suppressed · sorted by priority
361 files, 136,345 lines, 723,964 tokens · run 1 (replay: codehelion report --run 1)
◆ the occurrence a group is measured against
open one: codehelion explain f7f71e71 · list every group: --limit 0
```

見出しの先頭に来るのは順位づけの値です。一覧はこの値の順に並んでいるので、並び順をそのまま縦に読めます。`◆` はそのグループの基準になっている出現箇所、つまり最初に開くべき一件を指します。見出しの末尾にある識別子は `codehelion explain` が受け付ける最短の prefix なので、一覧からそのままグループを開けます。

`--decoration ascii` は同じ一覧を ASCII の範囲だけで描き、`--decoration none` はツリーそのものを落とします。上限の発火や何にも一致しなかったルールなど、実行そのものを限定する情報は標準エラー出力に回り、標準出力のレポートはパイプに流せる状態を保ちます。

```text
⚠ warning: candidate search was truncated by high frequency, high frequency postings; duplication the tree contains may be missing from this report
```

`-v` は各グループの順位づけの根拠を追加します。このモードでは測れなかった similarity の次元も含みます。

```text
 #1  0.62  type-1 ×2  188 tokens  f7f71e71
     within one file, identifiers 0.95
     confidence 0.82, maintenance risk 0.36, refactoring difficulty 0.17 (2 instances, 188-188 tokens, 188 repeated, 1.00 similarity, 1 file(s))
     similarity: composite 1.00 (lexical 1.00, structural 1.00, control-flow 1.00, type n/a, api 1.00); cohesion 1.00; confidence high [structural-verify-v1]
     content entropy: 5.02 bits
     body evidence: loop no, recognised allocation no, at least 15 call site(s)
     ├─ ◆ crates/codehelion-cli/src/scan/structural/reporting.rs:698-719    [finding 0300f485]
     └─   crates/codehelion-cli/src/scan/structural/reporting.rs:802-823    [finding 18957a06]
```

`-vv` は実行そのものの記録を追加します。候補パイプラインの段階ごとの通過数、適用された上限、そして完全な識別子です。

## 繰り返しスキャンする理由

重複は一度で出そろうものではありません。ある修正を二か所目に写したとき、同じ問題を同じ週に二人が別々に解いたとき、そして既存の実装を探しに行く理由のないコードが生成されたときに、その都度また増えます。厄介なのは重複が存在すること自体ではなく、見失われることです。誰も判断を覚えていないコピーは毎回のスキャンで報告され直し、残すと決めたはずのコピーはまた議論の対象になります。

安定した識別子と baseline は、そのためにあります。

## 特長

- **ビルド不要のスキャン** — エラー耐性のある lexer が Rust / C / C++ のソースを直接読むため、言語が混在するツリーも一度に、同じ基準で走査できます。コンパイラ・ビルドシステム・`compile_commands.json` はいずれも不要です。
- **安定した finding ID** — finding は行番号ではなく内容の fingerprint で名前を持ちます。同じ入力からは常に同じ識別子と同じグループ順序が得られ、これが抑制設定と baseline をリファクタリングをまたいで持続させます。
- **単一スコアではなく根拠** — 欠落を伴うクローンは lexical / structural / control-flow / type / API の similarity を個別に報告し、clone confidence・maintenance risk・refactoring difficulty を並べて示します。そのモードで測れない次元は推測せず、測定なしとして報告します。
- **見える上限** — 発火したリソース上限（ファイルサイズ・parse timeout・候補 budget）はすべてレポートに計上されます。候補 budget が探索を打ち切るほど大きなツリーでは、未検査のまま残したペア数を明示し、部分的な答えを完全な答えとして提示しません。
- **構造としてのローカル実行** — ネットワークアクセスの禁止と対象ツリーを実行しない方針は、運用上の約束ではなく lint と依存ポリシーで強制しています。`clippy.toml` が scan path でのプロセス起動とソケットを禁止し、`cargo-deny` が主要な HTTP スタックを依存グラフごと拒否します。

## インストール

```sh
cargo install codehelion
```

生成されるのは `codehelion` という自己完結の単一バイナリで、SQLite は同梱されています。チェックアウトからビルドする場合は次のとおりです。

```sh
cargo install --path crates/codehelion-cli
```

CLI と Semantic 以外のコンポーネントには Rust 1.85 以降が必要です。任意の Rust Semantic helper は別途 Rust 1.95 以降でのビルドを必要としますが、この要件が CLI の MSRV を引き上げることはありません。

Semantic スキャンでは、解析したい言語ごとの helper も必要です。helper を `PATH` に導入し、`doctor` で protocol とコンパイラの利用可否を確認してください。

```sh
cargo install codehelion-backend-rust
cargo install codehelion-backend-clang # システムの libclang も必要
codehelion doctor
```

## 使い方

```sh
codehelion scan               # カレントディレクトリをスキャンし text レポート
codehelion scan --mode structural           # gapped（Type-3）クローンも検出
codehelion scan --mode semantic             # コンパイラが解決した型で比較（helper が必要）
codehelion scan --format json --output report.json path/to/repo
codehelion scan --format sarif --output report.sarif   # SARIF 2.1.0 ログ
codehelion scan -v            # 各グループの根拠となる数値を追加（-vv で実行診断まで）
codehelion scan --quiet       # 見出しと要約を省き、グループだけを出力
codehelion scan --limit 0     # 全クローングループと全メンバーを列挙
codehelion scan --untrusted   # 素性の分からないツリーを低い上限で読む
codehelion report             # 最新の完了済みスキャンを再描画
codehelion report --run 1     # 特定の記録済みスキャンを再描画
codehelion explain <ID>       # ローカルデータベースから finding を表示
codehelion explain <ID> --format json
codehelion baseline create    # 最新の finding を baseline として固定
codehelion cache status       # ローカルデータベースの場所とサイズ
codehelion cache clear --force # ローカル監査データベースを恒久的に削除
codehelion config init        # コメント付き codehelion.toml テンプレートを生成
codehelion config show        # 有効な設定を表示
codehelion doctor             # 利用可能な解析コンポーネントを表示
```

主な scan の制御項目:

- `--config <file>` と `--db <path>` は設定ファイルとローカルデータベースを選びます。
- `--jobs <n>` は frontend の read/lex worker 数を指定します（host parallelism の 4 倍まで）。clone grouping と report rendering は serial です。`--no-ignore` は無視対象のファイルも読みます。
- `--baseline <file>` は判断済みの finding と比較します。`--show-suppressed`、`--show-siblings`、`--show-near-misses` は text 出力を展開します。JSON と SARIF には常にこれらのデータが含まれます。
- `-v` / `-vv` は各グループについて書く量を、`--limit <n>` は列挙するグループ数を決めます。`--quiet` はグループだけを出力します。`--color <auto|always|never>` は端末判定を上書きし、`NO_COLOR` にも従います。
- `--decoration <auto|unicode|ascii|none>` は一覧を描くグリフを選びます。色とは違って出力先には従いません。ファイルに書き出したレポートも端末と同じツリーを保ちます。エスケープシーケンスと違い、罫線素片はファイルの中でも読めるからです。`auto` は Windows を除いて罫線素片を使います。Windows のコンソールはアクティブなコードページ次第で描画が変わるためです。
- `--include-trivial` は Structural / Semantic モードで predicate family を計測済みの priority に戻します。
- `--fail-on-findings` は visible finding が残ると exit code 3 を返します。
- `--compare-build-variants` と `--compare-languages` は独立した Semantic comparison を要求し、通常の scan partition を混ぜません。
- `--allow-execution=build-script` は、Semantic helper がプロジェクトの build script を実行するための明示的な opt-in 許可です。これが無ければ scan 対象のコードは実行されず、`--untrusted` でも実行は許可されません。
- `cache clear --force` はローカル監査データベースを恒久的に削除します。常に明示的な確認フラグが必要です。

### 終了コード

- `0`: コマンドは成功しました。
- `1`: 実行上のエラーにより完了できませんでした。
- `2`: コマンドラインの指定が不正です。
- `3`: `scan --fail-on-findings` が 1 件以上の visible finding を検出しました。

### レポートの並べ替え

レポートは既定で合成された priority 順に並びます。priority は複数の指標を重み付けして束ねた値なので、目の前の作業がそのうちのひとつの指標そのものである場合は、その軸で直接並べ替えられます。

```sh
codehelion scan --sort duplicated-tokens    # 繰り返されているトークン量が多い順
codehelion scan --sort instances            # 複製された箇所が多い順
codehelion scan --mode structural --sort identifier-jaccard # 識別子の一致度が高い順
```

保守性を目的とする場合は、`--sort identifier-jaccard` に下限を付けるのが当たりを引きやすい方法です。識別子がまだ一致している複製は、まだ誰も分岐させていない複製であり、共通関数ひとつで置き換えられる余地が残っています。

```sh
codehelion scan --mode structural --sort identifier-jaccard --min-identifier-jaccard 0.7
```

この下限は同じ検出結果に対する見え方の指定です。テキスト表示の対象を決めるだけで、集計値・エクスポート・記録内容のいずれも変えません。識別子の一致度はユニット全体に対して測るため、fragment を報告する実行では比較する値がなく、その分を「表示しなかった件数」として明示します。

### baseline

検出結果はクローングループにまとめられ、グループとメンバーそれぞれが安定 ID を持ちます。既定の text レポートは各メンバーを `[finding <ID>]` と表示するため、そのまま `codehelion explain <ID>` に渡せます。この ID で抑制・baseline 登録・後日の参照ができます。

判断済みの finding は `codehelion baseline create` で凍結でき、以降のスキャンはそれを隠します。ローカルに残るスキャン履歴とは別に、プロジェクトが明示的に持ち続けられる前後比較が baseline です。

```sh
codehelion scan                       # ツリーを読む
codehelion baseline create .          # 起点を記録する
# ... 重複を減らす ...
codehelion scan --baseline codehelion-baseline.json --baseline-mode compare
```

`compare` は何も隠しません。各グループを「baseline が凍結したもの」と「そうでないもの」に分けて報告し、消えたトークン量と現れたトークン量を並べて出します。この 2 つが揃っていないと、大きな重複 4 件を解消して小さな重複 20 件が現れた状態が退行に見えてしまいます。また重複の解消はその周辺のコードも書き換えるため、組み替えの結果として現れるグループは新しい ID を持ちます。直前までエントリがあった場所に立っているグループは、誰かが足した重複としてではなく、そこに立っているものとして報告されます。

BuildVariant または detector version が異なる場合は、履歴を引き継がず現行スキャンから baseline を作り直します。

## 成果物検査（任意）

`artifact` コマンドは WASM、ELF、Mach-O、PE/COFF、静的アーカイブをローカルで読み取り、観測済みサイズ、重複したコードとデータ、retained size、ソース位置の根拠を報告します。読むのはバイト列だけで、対象の成果物をロードすることも実行することもありません。

```sh
codehelion artifact analyze path/to/binary
codehelion artifact report              # 最新の保存済み解析を再描画
codehelion artifact report --analysis 1 # 特定の保存済み解析を再描画
codehelion artifact compare before/binary after/binary
codehelion artifact calibration                 # 最新の完了済みソーススキャンを集計
codehelion artifact calibration --source-run 1  # 特定のソーススキャンを集計
```

デバッグ情報は ELF build ID、Mach-O UUID、または PE CodeView/PDB identity が一致した場合にだけ受け入れます。`artifact analyze --debug-file companion` は source scan なしでも native debug companion を検査できます。source-artifact correlation を要求する場合にだけ `--source-run` と `--build-variant` を追加してください。`--build-variant manifest.json` を渡した場合、build variant の identity には正規化した JSON 値を使うため、空白や object member の順序は identity を変えません。

artifact operation は既定で 512 MiB を超える入力を拒否し、parse・相関・永続化・render を含む全 worker 処理に 30 秒の期限を適用します。timeout 時には停止した段階を報告します。どちらも `--max-bytes` と `--timeout-seconds` で調整できます。Linux では `--max-memory-bytes <bytes>` により worker の仮想メモリ上限も強制します。ほかの OS ではこのオプションを黙って無視せず、エラーとして返します。`artifact report` 用に保存する versioned IR には別途 64 MiB の上限があり、保存対象の詳細がこれを超える分析は partial なデータベースレコードを残さずに失敗します。

## 設定

`codehelion scan` はスキャンルートの `codehelion.toml`（任意）を読み込みます。`codehelion config init` で全項目コメント付きのテンプレートを生成できます。主な項目:

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
# parse-timeout-ms = 10000          # 決定的な parse 作業量上限（wall-clock time ではない）
# helper-timeout-ms = 300000       # Semantic helper 応答の期限
# posting-cap = 64                  # 未設定ならモードごとの既定値のまま
# pair-budget = 1000000             # ペア生成 pass ごと。pass 間で共有しない
# near-miss-delta = 0.05            # Type-3 の閾値直下を診断表示する Structural 幅
# near-miss-cap = 1000              # report ごとに保持する診断 near miss 数
# sibling-candidate-budget = 50000  # group 後の Structural sibling 比較数
# sibling-per-group-cap = 8         # primary group ごとに保持する不完全 mirror 数
# sibling-total-cap = 1000          # report 全体で保持する不完全 mirror 数
# verification-budget = 1000000     # 精密検証に送る Structural pair 数
# max-alignment-cells = 4000000     # Structural alignment ごとの動的計画法セル数
# max-component = 1024
```

split-pairs は、同じ完全なクローングループに入らない検証済みペアを制御します。既定では非表示にせず、完全なグループより後ろに表示します。width-family は整数幅だけが違う関数群を制御し、既定では隠します。macro・generic・template でその関数群を一度だけ書けるなら、"report" に設定してください。これらの分類は Structural と Semantic scan で適用され、Fast scan では利用できないことを明示します。

完了したスキャンはローカル SQLite に保存され、text / JSON / SARIF レポートはそのスナップショットから export します。ツリーと設定が変わらなければ既存の完了 run を再利用し、`--no-reuse` なら新しい run を記録します。group の identity が変わっても十分な member content を共有していれば、保存された lineage が 2 つの run を結びます。baseline は、プロジェクトが受け入れた finding を明示的に残すためのものです。

各 scan は既定で `.codehelion/audit.db` に永続的なローカル監査データベースを作ります。置き場所は scan root を含む Git リポジトリの直下で、サブディレクトリを scan したときに新しいデータベースを作らずリポジトリのものを使い続けるためです。どのリポジトリにも属さない scan root は自分の下に持ちます。場所は `--db <path>` で上書きできます。リポジトリの `.gitignore` に `.codehelion/` を追加してください。このデータベースは捨ててよい build cache ではありません。

一方 `codehelion.toml` は scan root 自身からしか読まず、親ディレクトリから継承することはありません。scan はどの設定に従ったかとその出所を報告するものであり、読んでいる木より上にある誰も指定していないファイルはそれに当たらないからです。

`.h` は C と C++ が共有する唯一の拡張子で、どちらの文法で読むかがその中身の見え方を決めます。C++ ヘッダを C として読むと、エラー回復によって何も宣言しない形へ崩れ、本来の重複を隠す一方でクラス本体どうしの重複を捏造します。`detect` は拡張子が曖昧でないファイルを数えて多数派に従います。数えるものが無い木、つまりヘッダのみのライブラリでは、ヘッダ自身を読んで C++ にしか書けない綴りを探し、1 つでも見つかればその run 全体が C++ になります。この選択は run の build variant に含まれるため、異なる文法で読んだ結果どうしが比較されることはありません。

## 制限

**finding が測るのは保守性であってサイズではありません。** finding が示すのは読み手が同期を取り続ける必要のあるコードであり、コンパイラが出力するバイト数ではありません。最適化器はソース上で重複したままのコードを日常的に畳むため、報告されたクローンを解消しても成果物が小さくなるとは限りません。

**Fast モードは読み切れない量を報告します。** boilerplate・テストコード・整数幅の関数群に対する抑制ポリシーは構造分類を必要とするため、Fast モードでは適用できず、その旨をレポートに明示します。ある程度以上の規模のツリーで上から読んでいける一覧がほしい場合は `--mode structural` を使ってください。

**欠落や編集のあるコピーは検出しにくくなります。** codehelion はミラーの整合性検査ツールではありません。Structural detector は、候補にならないほど差異が大きい場合、ほかの点では似ているミラーを見逃すことがあります。

**大きなツリーでは上限に達します。** 候補 budget と高頻度 posting の上限が探索範囲を区切ります。どちらかに達した実行は、未検査のまま残した量を報告します。索引はメモリ上に置くため、非常に大きなツリーではディスク容量ではなくこれらの上限が効きます。

**成果物検査はシンボルに依存します。** strip 済みのバイナリからはほとんど何も得られないため、strip していないビルドか、identity を検証できるデバッグ情報を渡してください。レジスタと即値の違いを吸収する重複検出は x86 でのみ実装しており、ほかのアーキテクチャではバイト単位で一致する重複だけを検出します。成果物をソースへ対応づける経路は各シンボルから名前を読み取るもので、これは Rust と Itanium C++ ABI について行います。Microsoft ABI で装飾された C++ 成果物も、サイズと重複については読み取りますが、ソースとの対応は推測せず「対応なし」と報告します。

**監査データベースは移行しません。** 別のスキーマで書かれたデータベースは変換せずに拒否するため、退避してから再スキャンしてください。これは 1.0 までに変更します。

## 開発

よく使う操作は `Makefile` にまとめてあります（一覧は `make help`）。

```sh
make format        # 自動修正: clippy --fix + cargo fmt
make format-check  # フォーマット検証
make lint          # clippy を警告エラー扱いで実行
make test          # テスト実行
make check         # format-check + lint + 境界検査 + test + doc
make audit         # cargo-deny（脆弱性・禁止クレート・ライセンス）
make coverage      # HTML カバレッジレポート（cargo-llvm-cov が必要）
make hooks         # pre-commit git フックを導入
```

ガードレール: 設定を固定した `rustfmt`、`pedantic` + `nursery` を警告エラー扱いにした `clippy`（`unsafe` は禁止）、依存関係の advisory・ban・license を確認する `cargo-deny`、scan path のプロセス起動と network socket を禁止する `clippy.toml`、対象コードと同時に書くテスト、`make check` 一式を実行する pre-commit フック。

検出精度は `corpus/` 配下のコーパスで測ります。コーパスが持つのは実プロジェクトそのものではなく、それに対する手書きの verdict です。それぞれの半分が何を答えられて何を答えられないかは `corpus/README.md` に書いてあります。

helper の protocol handshake は `crates/codehelion-helper-conformance/` で検証します。CLI 側が生成した protocol の記述に対して突き合わせるのではなく、別々にビルドした helper のバイナリを実際に通します。

## 貢献

[CONTRIBUTING.md](CONTRIBUTING.md) を参照してください。セキュリティ上の問題は公開 issue ではなく [SECURITY.md](SECURITY.md) の手順で報告してください。

## ライセンス

[Apache License, Version 2.0](LICENSE) で提供します。
