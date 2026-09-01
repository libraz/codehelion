# codehelion

[![CI](https://img.shields.io/github/actions/workflow/status/libraz/codehelion/ci.yml?branch=main&label=CI)](https://github.com/libraz/codehelion/actions)
[![crates.io](https://img.shields.io/crates/v/codehelion.svg)](https://crates.io/crates/codehelion)
[![codecov](https://codecov.io/gh/libraz/codehelion/branch/main/graph/badge.svg)](https://codecov.io/gh/libraz/codehelion)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](https://github.com/libraz/codehelion/blob/main/LICENSE)
[![Rust](https://img.shields.io/badge/Rust-1.98%2B-orange?logo=rust)](https://www.rust-lang.org)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey)](https://github.com/libraz/codehelion)

Rust / C / C++ の重複ロジックを検出し、スキャンをまたいで同じ重複を追い続けるツールです。

codehelion はソースを直接読みます。ビルドも compilation database もネットワークも要りません。完全一致・リネーム・欠落を伴うコピーを検出し、判定に使った複数の指標を並べて報告し、各 finding には無関係な編集では変わらない内容由来の識別子を付けます。一度判断した重複は判断済みのまま残り、数か月後のスキャンを前回のスキャンと突き合わせられます。

処理はすべて実行したマシンの中で完結します。ソースコードも解析結果も外部に送信せず、ネットワークへの依存を持たず、実行分類ごとの許可フラグを渡さないかぎり読み取ったコードを実行しません。

ビルド不要の解析モードが 2 つと、任意のコンパイラ補助モードが 1 つあります。**Fast** はトークンレベルの Type-1（完全一致）・Type-2（識別子のリネーム、リテラルの変更）検出です。比較前にコメントと空白を除くため、コメントだけの編集でひとつの finding が 2 つに割れることはありません。**Structural** は Type-3 検出、つまり文の追加・削除・変更を伴うコピーの検出を加え、判定根拠となった次元別の similarity を報告します。**Semantic** は別途導入する Rust / Clang helper を動かし、CLI に compiler API をリンクせずにコンパイラが解決した型と名前の情報を取り込みます。

codehelion は 1.0 前です。コマンドラインの形・レポート形式・データベースのレイアウトはリリース間で変わり得ます。

## レポートの見え方

codehelion 自身のツリーに対する Structural モードの実行結果です（先頭 3 グループ）。

```text
codehelion scan · structural mode · ~/src/codehelion

 #1  0.67  type-1 ×2  240 tokens  0f5065d5
     ├─ ◆ crates/codehelion-cli/src/scan/store.rs:177-205       tree_changes
     └─   crates/codehelion-cli/src/scan/structural/store.rs:145-173  tree_changes

 #2  0.62  type-1 ×2  188 tokens  f7f71e71
     ├─ ◆ crates/codehelion-cli/src/scan/structural/reporting.rs:749-770
     └─   crates/codehelion-cli/src/scan/structural/reporting.rs:853-874

 #3  0.59  type-1 ×2  128 tokens  814ddea4
     ├─ ◆ crates/codehelion-frontend-c/src/ir.rs:1822-1836      line_column
     └─   crates/codehelion-frontend-rust/src/ir.rs:887-901     line_column

... and 956 more groups (--limit 0 lists every one)

1,226 groups (type-1 76, type-2 190, type-3 960) · 267 suppressed · sorted by priority
supplemental: 515 siblings (--show-siblings; 80 dropped by search ceilings), 1,000 near misses (--show-near-misses; 3,800 dropped by the retention cap)
369 files, 154,952 lines, 826,558 tokens · run 1 (replay: codehelion report --run 1)
◆ the occurrence a group is measured against · ×N the number of occurrences
open one: codehelion explain 0f5065d5 · list every group: --limit 0
```

見出しの先頭に来るのは順位づけの値です。一覧はこの値の順に並んでいるので、並び順をそのまま縦に読めます。`◆` はそのグループの基準になっている出現箇所、つまり最初に開くべき一件を指します。見出しの末尾にある識別子は `codehelion explain` が受け付ける最短の prefix なので、一覧からそのままグループを開けます。

`--decoration ascii` は同じ一覧を ASCII の範囲だけで描き、`--decoration none` はツリーそのものを落とします。上限の発火や何にも一致しなかったルールなど、実行そのものを限定する情報は標準エラー出力に回り、標準出力のレポートはパイプに流せる状態を保ちます。

```text
⚠ warning: candidate search was truncated by high frequency, high frequency postings; duplication the tree contains may be missing from this report
```

`-v` は各グループの順位づけの根拠を追加します。このモードでは測れなかった similarity の次元も含みます。

```text
 #1  0.67  type-1 ×2  240 tokens  0f5065d5
     across directories, identifiers 1.00
     confidence 0.86, maintenance risk 0.44, refactoring difficulty 0.19 (2 instances, 240-240 tokens, 240 repeated, 1.00 similarity, 2 file(s))
     similarity: composite 1.00 (lexical 1.00, structural 1.00, control-flow 1.00, type n/a, api 1.00); cohesion 1.00; confidence high [structural-verify-v1]
     content entropy: 4.91 bits
     body evidence: loop no, recognised allocation no, at least 26 call site(s)
     ├─ ◆ crates/codehelion-cli/src/scan/store.rs:177-205       tree_changes  [finding c8c5aae7]
     └─   crates/codehelion-cli/src/scan/structural/store.rs:145-173  tree_changes  [finding 63fd17f8]
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

任意の Rust Semantic helper を含め、すべて Rust 1.98 以降が必要です。この下限は helper が使う解析ライブラリが決めており、コンポーネントごとに分かれてはいません。

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
codehelion baseline update    # 最新スキャンが報告しなくなった baseline 項目を落とす
codehelion cache status       # ローカルデータベースの場所とサイズ
codehelion cache prune --force # 保持上限を適用してデータベースを圧縮
codehelion cache clear --force # ローカル監査データベースを恒久的に削除
codehelion config init        # コメント付き codehelion.toml テンプレートを生成
codehelion config show        # 有効な設定を表示
codehelion doctor             # 利用可能な解析コンポーネントを表示
```

主な scan の制御項目:

- `--config <file>` と `--db <path>` は設定ファイルとローカルデータベースを選びます。
- `--jobs <n>` は frontend の read/lex worker 数を指定します（host parallelism の 4 倍まで）。clone grouping と report rendering は serial です。省略した場合の worker 数はホストの並列度から自動で決まります。
- `--no-ignore` は無視対象のファイルも読みます。`--follow-links` はシンボリックリンクを辿ります（既定では辿らず、種別ごとに数えて報告します）。`--compile-commands <path>` は自動選択の代わりに読む compilation database を指定します。
- `--baseline <file>` は判断済みの finding と比較します。`--show-suppressed`、`--show-siblings`、`--show-near-misses` は text 出力を展開します。JSON と SARIF には常にこれらのデータが含まれます。`--siblings-by-signature` は Structural / Semantic モードでシグネチャによる sibling 生成を有効にします。既定では無効で、`--show-siblings` は text 表示だけを変えます。
- `-v` / `-vv` は各グループについて書く量を、`--limit <n>` は列挙するグループ数を決めます。`--quiet` はグループだけを出力します。省略した場合、text レポートはグループ 10 件と各グループの出現箇所 5 件までを列挙し、いくつ省いたかを述べます。`--limit <n>` が変えるのはグループ数だけで、両方の上限を外すのは `--limit 0` です。`--color <auto|always|never>` は端末判定を上書きし、`NO_COLOR` にも従います。
- `--decoration <auto|unicode|ascii|none>` は一覧を描くグリフを選びます。色とは違って出力先には従いません。ファイルに書き出したレポートも端末と同じツリーを保ちます。エスケープシーケンスと違い、罫線素片はファイルの中でも読めるからです。`auto` は Windows を除いて罫線素片を使います。Windows のコンソールはアクティブなコードページ次第で描画が変わるためです。
- `--include-trivial` は Structural / Semantic モードで predicate family を計測済みの priority に戻します。
- `--fail-on-findings` は visible finding が残ると exit code 3 を返します。
- `--compare-build-variants` と `--compare-languages` は独立した Semantic comparison を要求し、通常の scan partition を混ぜません。
- `--allow-execution=build-script` は、Semantic helper がプロジェクトの build script を実行するための明示的な opt-in 許可です。これが無ければ scan 対象のコードは実行されず、`--untrusted` でも実行は許可されません。
- `--untrusted` はどのプラットフォームでも scan の上限を下げます。ただし `--mode semantic` と併用する場合は helper プロセスに OS が強制するメモリ上限を要求するため、それを課せる Linux でのみ使えます。ほかの OS では、helper を無防備に走らせる代わりにエラーで停止します。
- `cache prune --force` はローカル監査データベースに保持上限を適用して圧縮します。既定では単体の artifact 解析を新しい順に 20 件、各種 comparison をそれぞれ新しい順に 20 件残します（`--keep-artifacts` と `--keep-comparisons` で変更できます）。保持済みの履歴を削除する操作なので確認フラグが必要です。
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

検出結果はクローングループにまとめられ、グループとメンバーそれぞれが安定 ID を持ちます。既定のレポートで見出しの末尾に出るのはグループの ID で、`[suppression] clone-ids` と baseline が受け取るのもこちらです。どちらもグループ単位で指定するものなので、メンバーの ID を書いても何にも一致しません。メンバーの ID は `-v` を付けたときに `[finding <ID>]` として表示されます。どちらの ID も `codehelion explain <ID>` で開けます。

判断済みの finding は `codehelion baseline create` で凍結でき、以降のスキャンはそれを隠します。ローカルに残るスキャン履歴とは別に、プロジェクトが明示的に持ち続けられる前後比較が baseline です。

```sh
codehelion scan                       # ツリーを読む
codehelion baseline create .          # 起点を記録する
# ... 重複を減らす ...
codehelion scan --baseline codehelion-baseline.json --baseline-mode compare
```

`compare` は何も隠しません。各グループを「baseline が凍結したもの」と「そうでないもの」に分けて報告し、消えたトークン量と現れたトークン量を並べて出します。この 2 つが揃っていないと、大きな重複 4 件を解消して小さな重複 20 件が現れた状態が退行に見えてしまいます。また重複の解消はその周辺のコードも書き換えるため、組み替えの結果として現れるグループは新しい ID を持ちます。直前までエントリがあった場所に立っているグループは、誰かが足した重複としてではなく、そこに立っているものとして報告されます。

BuildVariant または detector version が異なる場合は、履歴を引き継がず現行スキャンから baseline を作り直します。

baseline は閾値を凍結して CI で守るためのものです。リファクタの進み具合を自分で追うだけなら baseline は要りません。再スキャンして、前回の実行で上位にあったグループがどうなったかを述べるサマリ行と、そのグループが最新の実行に残っているかを述べる `codehelion explain <ID>` を読めば足ります。どちらもローカルのデータベースにすでにある実行から導出されるので、作るものも、同期を取り続けるものも、コミットするものもありません。

### リファクタ直後の再スキャン

スキャンは、終えたばかりのリファクタに対する検査でもあります。次の作業へ移る前に、書き換えたツリーをもう一度読ませてください。

```sh
codehelion scan --mode structural
```

読み方は規則ひとつです。書いたばかりのヘルパが、置き換えたはずの呼び出し元と同じグループに現れたら、その呼び出し元は置換漏れです。これを報告するものは他にありません。コンパイルは通り、挙動も変わらないため、テストが通ることはすべてのコピーが消えた証拠になりません。通常の規模のツリーならスキャンは数秒で終わるので、リファクタごとに 1 回走らせる運用が現実的に成り立ちます。

成果物も小さくなったかどうかは別の問いです。finding が名指しするのは読み手が同期を取り続ける必要のあるコードであり、コンパイラが出力するバイト数ではありません。そちらは `codehelion artifact analyze path/to/binary` が測ります。

`-v` でグループの下に出る類似度の内訳は、ファイルを開く前に読む価値があります。構造と制御フローが完全に一致していて識別子だけが一致しないグループは、同じ処理を別々の名前で 2 回書いたものであることが多く、違う部分を引数に取る 1 つの関数に畳めます。識別子まで一致するグループはコピーであることが多く、片方をそのまま消せます。これは数値の読み方であって、ツールが適用する規則ではありません。codehelion は各出現が何を共有しているかを報告するだけで、リファクタの判断は利用者に委ねます。

## 成果物検査（任意）

`artifact` コマンドは WASM、ELF、Mach-O、PE/COFF、静的アーカイブをローカルで読み取ります。読むのはバイト列だけで、対象の成果物をロードすることも実行することもありません。

観測済みサイズと重複したコードは、どのフォーマットについても報告します。それ以外は、そのフォーマット自身が確立できる量に限られます。retained size と shared size はコールグラフを必要とし、これを導けるのは WASM、ELF、静的アーカイブです。重複データは独立にサイズの付くデータ領域を必要とし、それを持つのは WASM です。ソース位置にはデバッグ情報が要ります。ELF なら DWARF、Mach-O なら identity の一致する dSYM、PE/COFF なら一致する PDB、WASM なら記録された source map の URL です。フォーマットが供給できない量は数値を作らず unavailable として報告し、何が足りなかったかを述べる assumption を並べます。

これらのコマンドが測るのはビルドされた成果物そのものであって、ソース側で重複を統合したら成果物から何が減るかを予測するものではありません。両者の隔たりは大きく、実測でもそうなります。あるプロジェクトでは、実コード 238 行（重複トークン 2,714）を消して、非圧縮で 3,554 バイト（0.14%）、Brotli 圧縮後で 584 バイト（0.09%）減りました。2 リリース後にクローングループ 14 件を統合したときは、非圧縮で 15,323 バイト（0.56%）に対し圧縮後は 928 バイト（0.13%）で、非圧縮側の 6% です。理由はリファクタより手前にあります。リンカと `wasm-opt` が出荷前に同一コードを畳んでおり、2.6 MiB の出荷 WASM モジュールに残っていたバイト単位で一致する重複は、実測で合計 20 バイトでした。ソース側の統合が効くのは、サイズの上限が非圧縮の値であるプロジェクト — メモリマップされるイメージ、ファームウェアイメージ、転送時のエンコード前で測る WASM モジュール — であり、上限を gzip / Brotli の後で測るプロジェクトにはほとんど効きません。

「ソース上に写しが何個あるか」と「バイナリ上に実体が何個あるか」は別の軸で、codehelion の探索モデルにあるのは前者だけです。ある実測では、回収できた 2,726 バイトのうち 1,730 バイト（63%）が、ソース上は 1 本のテンプレートでありながら、述語のクロージャ型が呼び出し箇所ごとに違うためバイナリ上では 14 個の別々の実体になっていたものでした。ソース上の写しは 1 つなので、この多重度を述べるクローングループは存在しません。同じツリーで codehelion が実際に報告したグループが説明したのは、残りの 996 バイト、つまり小さいほうです。

クローン検出が見つけられる写しは今も 1 つだけで、この多重度を述べるクローングループは今後も存在しません。ソーススキャンと相関させた場合は、別立てで報告します。`artifact analyze --source-run` は、成果物が複数の実体として出力したソース単位を、実体の個数と観測サイズとともに並べます。ここに出るバイト数は成果物が現に費やしている量であって削減量ではありません。ソース上の 1 本を統合しても実体は 1 つも減らず、この数値を下げるには実体化の回数そのものを減らすことになります。数えるのに必要なのは「マッピングが単一のソース単位を指したこと」だけなので、シンボル名さえあれば足り、デバッグ行情報は要りません。

```sh
codehelion artifact analyze path/to/binary
codehelion artifact analyze path/to/binary --format csv  # json も可。既定は text
codehelion artifact analyze path/to/binary --untrusted   # サイズ・時間・メモリの上限を下げる
codehelion artifact report              # 最新の保存済み解析を再描画
codehelion artifact report --analysis 1 # 特定の保存済み解析を再描画
codehelion artifact compare before/binary after/binary
codehelion artifact calibration                 # 記録済みの計測を集計
codehelion artifact calibration --source-run 1  # 特定のソーススキャンを集計
codehelion artifact calibration --baseline earlier.json  # 以前の集計と並べる
```

`artifact calibration` は計測を取るコマンドではなく読むコマンドなので、計測が 1 件も無ければ集計する対象もありません。計測を記録するのは `artifact compare` で、`--source-run` と `--clone-group` を `--before-build-variant` / `--after-build-variant` と併せて渡したときです。そのグループについて保存済みの見積もりと、2 つの成果物が実際に示したサイズ差を並べます。ここで必要になる見積もりは、先に `--source-run` と `--build-variant` を付けて実行した `artifact analyze` が残します。

`--baseline <file>` には、以前 `artifact calibration --format json` が書き出した集計レポートを渡します。全体と stratum ごとに、各誤差統計が現在値との間でどれだけ動いたかを並べて表示します。行うのは比較と報告だけで、閾値は課さず、差が出ても失敗にはしません。calibration レポートのスキーマが異なるものは、比較せずエラーとして拒否します。

キャリブレーション付きの比較から出てくる `verified_savings_bytes` は、2 つの成果物のあいだで観測されたサイズ差をまるごと、`--clone-group` で名指しした 1 つのクローングループに帰属させた値です。この比較が確かめるのは、両方の成果物が同じフォーマットであることと、宣言された build variant が同じであることだけで、それ以上は確かめません。依存の更新やツールチェーンの変更を一緒に拾ったビルド対では、その差も含めてリファクタリングの計測値として報告されます。この数値が言葉どおりの意味を持つのは、2 つの成果物がそれ以外の点で何も違わないときだけです。

デバッグ情報は ELF build ID、Mach-O UUID、または PE CodeView/PDB identity が一致した場合にだけ受け入れます。`artifact analyze --debug-file companion` は source scan なしでも native debug companion を検査できます。source-artifact correlation を要求する場合にだけ `--source-run` と `--build-variant` を追加してください。`--build-variant manifest.json` を渡した場合、build variant の identity には正規化した JSON 値を使うため、空白や object member の順序は identity を変えません。

`--build-variant` に渡すのは自分で書くファイルで、どこかにある既存のファイルを探すものではありません。中身は自由に決められます。それによって得られるのは、同じ条件でビルドされた成果物どうしだけが比較される、という保証です。

```sh
echo '{"profile":"release","target":"wasm32","toolchain":"emcc-5.0.2"}' > build-variant.json
codehelion artifact analyze dist/app.wasm --build-variant build-variant.json --source-run 2
```

source run にも build variant があり、レポートはその digest を表示します。両者は別々の条件 — ソースをどう読んだか、成果物をどうビルドしたか — であり、突き合わせるのではなく並べて記録します。manifest に書き写すべき source 側の digest は存在しません。

`artifact analyze` と `artifact compare` は既定で 512 MiB を超える入力を拒否し、parse・相関・永続化・render を含む全 worker 処理に 30 秒の期限を適用します。timeout 時には停止した段階を報告します。どちらも `--max-bytes` と `--timeout-seconds` で調整できます。Linux では `--max-memory-bytes <bytes>` により worker の仮想メモリ上限も強制します。ほかの OS ではこのオプションを黙って無視せず、エラーとして返します。`--untrusted` はこの 3 つをまとめて締めるため Linux 限定です。ほかの OS では、強制できないメモリ上限のまま素性の分からない成果物を読む代わりにエラーで停止します。`artifact report` と `artifact calibration` はローカルデータベースにあるものを読み直すだけで、worker を挟まずプロセス内で動くため、これらのオプションは対象外です。`artifact report` 用に保存する versioned IR には別途 64 MiB の上限があり、保存対象の詳細がこれを超える分析は partial なデータベースレコードを残さずに失敗します。

## 設定

`codehelion scan` はスキャンルートの `codehelion.toml`（任意）を読み込みます。`codehelion config init` で全項目コメント付きのテンプレートを生成できます。主な項目:

```toml
# min-clone-tokens = 20             # 報告する最小クローン長（トークン数）
# literal-normalization = "full"    # "preserve" / "category" / "full"
# database = ".codehelion/audit.db" # ローカルデータベースの場所
# jobs = 4                           # frontend read/lex worker 数（host parallelism の 4 倍まで）。
                                    # grouping/reporting は serial。省略すると自動で決まり、
                                    # それが組み込みの既定。4 は例であって既定値ではない

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
# clone-ids = []                    # 安定クローングループ ID（hex、前方一致は 8 文字以上）
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

完了したスキャンはローカル SQLite に保存され、text / JSON / SARIF レポートはそのスナップショットから export します。ツリーと設定が変わらなければ既存の完了 run を再利用し、`--no-reuse` なら新しい run を記録します。group の identity が変わっても十分な member content を共有していれば、保存された lineage が 2 つの run を結びます。レポートは各 group について、identity をそのまま保ったのか、どの group から引き継いだのかを示します。合計欄は、比較対象となった直前の run で上位にあった group がその後どうなったかを示します。追跡する件数は `report.churn-top` で決まり、既定は 100 です。baseline は、プロジェクトが受け入れた finding を明示的に残すためのものです。

各 scan は既定で `.codehelion/audit.db` に永続的なローカル監査データベースを作ります。置き場所は scan root を含む Git リポジトリの直下で、サブディレクトリを scan したときに新しいデータベースを作らずリポジトリのものを使い続けるためです。どのリポジトリにも属さない scan root は自分の下に持ちます。場所は `--db <path>` で上書きできます。リポジトリの `.gitignore` に `.codehelion/` を追加してください。このデータベースは捨ててよい build cache ではありません。

一方 `codehelion.toml` は scan root 自身からしか読まず、親ディレクトリから継承することはありません。scan はどの設定に従ったかとその出所を報告するものであり、読んでいる木より上にある誰も指定していないファイルはそれに当たらないからです。

`.h` は C と C++ が共有する唯一の拡張子で、どちらの文法で読むかがその中身の見え方を決めます。C++ ヘッダを C として読むと、エラー回復によって何も宣言しない形へ崩れ、本来の重複を隠す一方でクラス本体どうしの重複を捏造します。`detect` は拡張子が曖昧でないファイルを数えて多数派に従います。数えるものが無い木、つまりヘッダのみのライブラリでは、ヘッダ自身を読んで C++ にしか書けない綴りを探し、1 つでも見つかればその run 全体が C++ になります。この選択は run の build variant に含まれるため、異なる文法で読んだ結果どうしが比較されることはありません。

## 制限

**finding が測るのは保守性であってサイズではありません。** finding が示すのは読み手が同期を取り続ける必要のあるコードであり、コンパイラが出力するバイト数ではありません。最適化器はソース上で重複したままのコードを日常的に畳むため、報告されたクローンを解消しても成果物が小さくなるとは限りません。

C++ と Rust では、同じシグネチャと同じ本体を持つ関数が identical code folding の対象になります。Type-1 の重複はリンカがすでに畳んでいる可能性が高く、識別子やリテラルが変わる Type-2 / Type-3 は機械語が別になることがあるため、サイズが目的ならこちらの方が調べる価値が高くなります。この 2 つは問題の大きさが違います。最適化済みのビルドでは、成果物の中にバイト単位まで一致したまま残っている量はごく僅かで、レジスタや即値の違いを正規化して初めて一致する量はその数千倍あります。`codehelion artifact analyze` は exact と normalized の値を並べて報告するので、自分のビルドでの比率は仮定ではなく実測で確かめられます。

**圧縮後のサイズは、非圧縮のサイズほどには動きません。** 重複の解消が成果物から取り除くのは同じバイト列の再出現であり、同じバイト列の再出現は圧縮器が真っ先に畳むものです。非圧縮のバイナリは取り除いた分だけおおむね小さくなりますが、圧縮後はそれよりはるかに小さくしか動きません。圧縮器は 2 つ目のコピーに対してすでにほとんど何も払っていなかったからです。サイズの上限が圧縮後の値であるプロジェクトにとって、重複の解消はそのための手段ではありません。上限が非圧縮の値であるプロジェクト — メモリマップされるイメージ、組み込みのファームウェアイメージ、転送時のエンコード前で測る WASM モジュール — にとっては手段になります。比率はどこかから持ってくるのではなく、自分のリファクタの前後で両方を測ってください。ここでその値を再導出する仕組みはありません。

**Fast モードは読み切れない量を報告します。** boilerplate・テストコード・整数幅の関数群に対する抑制ポリシーは構造分類を必要とするため、Fast モードでは適用できず、その旨をレポートに明示します。ある程度以上の規模のツリーで上から読んでいける一覧がほしい場合は `--mode structural` を使ってください。

**欠落や編集のあるコピーは検出しにくくなります。** Structural / Semantic モードには sibling channel が 2 つあります。similarity channel は常に動き、グループの canonical member に近いと測られ、そのグループがすでに占めているファイルの中にある未グループの unit を保持します。signature channel は `--siblings-by-signature` を指定したときだけ動き、既定では無効です。有効にすると、グループの canonical function と正規化済みシグネチャが一致し、まだグループ化されていない関数が同じディレクトリにある場合、低信頼度の sibling として保持できます。シグネチャが証拠になるのは、それが珍しいあいだだけです。そのため `limits.signature-sibling-max-units-per-signature` が許す数より多くの unit が共有するシグネチャは、探索から丸ごと除外されます。いくつのシグネチャを除外したか、いちばん広く共有されていたものがどれだけの unit に及んだかは、サマリが report します。この上限で除外された候補と、探索の上限で落ちた候補は別々に数えるので、どちらを動かすべきかが読み取れます。どちらも変更でき、件数はツリーと設定が決まれば一意に定まるため、実行環境ではなく設定の性質です。`--show-siblings` は text 表示だけを変え、JSON と SARIF には生成済みの sibling が残ります。別ディレクトリの mirror、変化したシグネチャ、sibling 探索の上限を超えた候補は、なお見逃すことがあります。codehelion はミラー整合性検査ツールではありません。すべての mirror を見つけたことや、同じシグネチャの本体が同じ動作をすることを証明するものではありません。

完全なコピーは保守負債ですが、内容がずれたコピーはその時点のバグです。そして検出しにくいのはずれたほうであり、手写しのミラーを監査する用途で欲しい順序とは逆になります。ある実測では、enum を文字列へ変換する対応表が 3 つのサーフェスに手写しされており、完全に写された 3 組はすべてグループになった一方、名前が 3 つ欠けている 1 組 — 実際にバグを起こしていた 1 組 — はどのグループにも入りませんでした。別の実測では、同じパスを組み立てる関数が 3 本あり、完全一致の 2 本はグループになり、早期 return を使うか else 節を使うかだけが違う 3 本目は `--show-siblings` にも `--show-near-misses` にも現れませんでした。どちらも見つけたのは手元の `grep` です。ですからグループが報告されたら、その隣にあるものを読んでください。グループに入らなかった同じ形の関数こそ、ずれたコピーがいちばん潜んでいそうな場所です。

**1 つのシグネチャで駆動する層に、このチャネルは何も与えません。** dispatch table や callback table によって 100 本の関数が同じ呼び出し形を持つ場所では、シグネチャは何も区別しません。そうした層について、このチャネルが出せる証拠はありません。それを言えるようにすることが共有数の上限の目的です。上限が無ければ、任意の関数どうしを組にした sibling が数千件並び、検討するまでは結果のように見えてしまいます。

**大きなツリーでは上限に達します。** 候補 budget と高頻度 posting の上限が探索範囲を区切ります。どちらかに達した実行は、未検査のまま残した量を報告します。索引はメモリ上に置くため、非常に大きなツリーではディスク容量ではなくこれらの上限が効きます。

**成果物検査はシンボルに依存します。** strip 済みのバイナリからはほとんど何も得られないため、strip していないビルドか、identity を検証できるデバッグ情報を渡してください。レジスタと即値の違いを吸収する重複検出は、ネイティブ機械語では x86 について実装しており、これとは別に WebAssembly についても、その opcode 列を正規化して行います。ほかのアーキテクチャ向けのネイティブ成果物では、バイト単位で一致する重複だけを検出します。成果物をソースへ対応づける経路は各シンボルから名前を読み取るもので、これは Rust と Itanium C++ ABI について行います。Microsoft ABI で装飾された C++ 成果物も、サイズと重複については読み取りますが、ソースとの対応は推測せず「対応なし」と報告します。

**WebAssembly モジュールのソース対応はシンボル単位までです。** ELF・Mach-O・PE/COFF は DWARF、identity の一致する dSYM、一致する PDB を通じてソース行に到達でき、クローングループの行範囲にバイトを帰属させられるのはこのソース行があるからです。コアモジュールが持つのは name セクションの関数名だけで行情報が無いため、対応づけは関数単位までにとどまり、クローングループの byte 帰属は unavailable になります。DWARF を出してビルドすれば行情報は得られますが、それは測っている対象そのもの — 通常はそれこそが検査の理由であるサイズ — を変えてしまいます。そのため各レポートは、別の問いに答えるビルドを要求するのではなく、name セクションで何が得られて何が得られないかを述べます。

**監査データベースは移行しません。** 別のスキーマで書かれたデータベースを変換することはないため、履歴はスキーマをまたいで引き継がれません。既定のパスでは、そのデータベースをそのまま残し、隣の `audit-v<スキーマ>.db` へ記録して、どちらのファイルを使ったかを報告します。`--db` で名前を指定したデータベースの場合は、指定されたパスを無視して別の場所へ書くことになるため、代わりにエラーとします。`doctor` はディレクトリ内の監査データベースをすべて挙げ、このビルドで開けるものと、実行が選ぶものを示します。これは 1.0 までに変更します。

## 精度

`make eval` による 0.4.0 時点の実測です。生成コーパスはリポジトリに入っているため、再現率の数値はチェックアウトだけで再現できます。ラベル付きケースがリポジトリに持つのは判定だけでソースは持たないため、適合率の数値を再現するには先に `corpus/scripts/materialize-labeled.sh` を実行する必要があります。それぞれが何を答えられて何を答えられないかは `corpus/README.md` を参照してください。

**再現率 — 生成された 10 の変異コーパス、クローン対 43 件・意図的な非クローン 11 件。** 生成コーパスは自分が含むクローンをすべて把握しているので再現率を測れます。適合率は測れません。作られたときのクローンだけにラベルが付いているため、ラベルのない本物のコピーを検出すると減点になってしまうからです。

| コーパス | Fast | Structural |
|---|---|---|
| rust | 0.7143 | 1.0000 |
| c | 0.8333 | 1.0000 |
| cpp | 0.8571 | 1.0000 |
| cpp-common-signature | 1.0000 | 1.0000 |
| rust-graded | 1.0000 | 1.0000 |
| rust-literals | 1.0000 | 1.0000 |
| rust-replaced | 1.0000 | 1.0000 |
| rust-negative | 1.0000 | 1.0000 |
| rust-partial | 1.0000 | 0.5000 |
| rust-divergent | 0.4000 | 0.8000 |

Fast モードは `rust` / `c` / `cpp` の type-3 クローンを1件も拾えません。これは調整の問題ではなく、構造パスを飛ばしたことの代償です。`rust-partial` は Structural が Fast を下回る唯一のコーパスです。`cpp-common-signature` はシグネチャ sibling チャネルのためにあります。9 本の関数が 1 つの呼び出し形を共有しており、これほど共有された形を証拠として出さないことが主要な結果に何の犠牲も強いないことを固定します。

restricted-semantic の6コーパスはここでは採点していません。登録済みルールはそれぞれ専用のテストが「なぜ一致したか / なぜ落としたか」を主張しており、問いの異なるルールをまたいで平均を取るより強い主張になるためです。

**適合率 — 実プロジェクトのラベル付きスナップショット8件、クローン対の判定 141 件・非クローンの判定 177 件。** これらのツリーで検出器が報告したグループにはすべて手書きの判定が付いているため、適合率を測れます。再現率は測れません。誰もそれらのプロジェクトのクローンを事前に数え上げていないからです。

| ケース | Structural 適合率 | 確認 | 棄却 |
|---|---|---|---|
| codehelion-store | 1.0000 | 2 | 0 |
| fast-yaml | 1.0000 | 1 | 0 |
| cjson | 0.8235 | 14 | 3 |
| bitflags | 0.7857 | 11 | 3 |
| spdlog | 0.5833 | 21 | 15 |
| serde-json | 0.5357 | 45 | 39 |
| lz4 | 0.5357 | 15 | 13 |
| tinyxml2 | 0.5263 | 10 | 9 |
| **全ケース** | **0.5920** | **119** | **82** |

8件のうち2件は本プロジェクト作者自身のもので、いずれも 1.0000 です。除くと全体は 0.5859 になります。この2件が担う判定は 201 件中3件なので、どちらにしてもこの数字は残り6プロジェクトのものです。

0.5920 はレポートを端から端まで読んだ場合の数字ですが、重複レポートはそう読むものではありません。ある重複の短い切り口は、それを含む長い所見の中で示されるため順序の中に自分の位置を持ちません。単独の所見を持つ 200 件の判定に対して:

| 並べ方 | p@10 | p@50 | MAP |
|---|---|---|---|
| priority | 1.0000 | 0.9600 | 0.9290 |
| size | 1.0000 | 0.9400 | 0.8772 |

どちらの並べ方でも上位10件に誤検出は入りません。全体の数字が言っているのは末尾が半分近くノイズだということで、priority 順と `--mode structural` を選択肢ではなく既定にしているのはそのためです。

判定が紐づくスナップショットは `corpus/scripts/materialize-labeled.sh` が取得するもので、再配布はしません。materialize されていないケースは満点ではなく「未採点」として報告されます。

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

ガードレール: 設定を固定した `rustfmt`、`pedantic` + `nursery` を警告エラー扱いにした `clippy`（`unsafe` は禁止）、依存関係の advisory・ban・license を確認する `cargo-deny`、scan path のプロセス起動と network socket を禁止する `clippy.toml`、対象コードと同時に書くテスト。pre-commit フックが走らせるのは `cargo fmt --check` と警告エラー扱いの `cargo clippy` だけで、数秒で終わる機械的な部分に絞っています。テスト・境界検査・パッケージング検査は `make check` の側にあり、push の前に実行します。

検出精度は `corpus/` 配下のコーパスで測ります。コーパスが持つのは実プロジェクトそのものではなく、それに対する手書きの verdict です。表を出すのは `make eval` で、現在の数値は[精度](#精度)にあります。それぞれの半分が何を答えられて何を答えられないかは `corpus/README.md` に書いてあります。

helper の protocol handshake は `crates/codehelion-helper-conformance/` で検証します。CLI 側が生成した protocol の記述に対して突き合わせるのではなく、別々にビルドした helper のバイナリを実際に通します。

## 貢献

[CONTRIBUTING.md](CONTRIBUTING.md) を参照してください。セキュリティ上の問題は公開 issue ではなく [SECURITY.md](SECURITY.md) の手順で報告してください。

## ライセンス

[Apache License, Version 2.0](LICENSE) で提供します。
