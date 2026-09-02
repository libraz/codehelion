# コマンドライン

各コマンドの `--help` が正本であり、このページより詳しい情報を持ちます。ここに書くのは全体の形です。

```sh
codehelion scan               # カレントディレクトリをスキャンし text レポート
codehelion scan --mode structural           # gapped（Type-3）クローンも検出
codehelion scan --mode semantic             # コンパイラが解決した型で比較（helper が必要）
codehelion scan --format json --output report.json path/to/repo
codehelion scan --format sarif --output report.sarif   # SARIF 2.1.0 ログ
codehelion scan -v            # 各グループの根拠となる数値を追加（-vv で実行診断まで）
codehelion scan --quiet       # 見出しと要約を省き、グループだけを出力
codehelion scan --limit 0     # 全クローングループと全出現箇所を列挙
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
codehelion history            # 範囲内のコミットを分類し、何を読んだかを述べる
codehelion seam               # 台帳が名指しする seam を計測
codehelion seam --suggest     # 共変更だけから seam の候補を提示
codehelion guard              # 変更を台帳に照らす
codehelion guard --deny-asymmetric  # seam の一部だけを触る変更があれば exit 3
codehelion guard --paths src/a.rs   # 編集前に、そのパスが属する seam を引く
```

## `scan`

ツリーを読み、その実行を記録します。主な制御項目は次のとおりです。

- `--config <file>` と `--db <path>` は設定ファイルとローカルデータベースを選びます。
- `--jobs <n>` は frontend の read/lex worker 数を指定します（host parallelism の 4 倍まで）。clone grouping と report rendering は serial です。省略した場合の worker 数はホストの並列度から自動で決まります。
- `--no-ignore` は無視対象のファイルも読みます。`--follow-links` はシンボリックリンクを辿ります（既定では辿らず、種別ごとに数えて報告します）。`--compile-commands <path>` は自動選択の代わりに読む compilation database を指定します。
- `--baseline <file>` は判断済みの finding と比較し、`--baseline-mode` が凍結済みグループを隠すか印を付けるかを決めます。`--show-suppressed`、`--show-siblings`、`--show-near-misses` は text 出力を展開します。JSON と SARIF には常にこれらのデータが含まれます。`--siblings-by-signature` は Structural / Semantic モードでシグネチャによる sibling 生成を有効にします。既定では無効で、`--show-siblings` は text 表示だけを変えます。
- `-v` / `-vv` は各グループについて書く量を、`--limit <n>` は列挙するグループ数を決めます。`--quiet` はグループだけを出力します。省略した場合、text レポートはグループ 10 件と各グループの出現箇所 5 件までを列挙し、いくつ省いたかを述べます。`--limit <n>` が変えるのはグループ数だけで、両方の上限を外すのは `--limit 0` です。`--color <auto|always|never>` は端末判定を上書きし、`NO_COLOR` にも従います。
- `--decoration <auto|unicode|ascii|none>` は一覧を描くグリフを選びます。色とは違って出力先には従いません。ファイルに書き出したレポートも端末と同じツリーを保ちます。エスケープシーケンスと違い、罫線素片はファイルの中でも読めるからです。`auto` は Windows を除いて罫線素片を使います。Windows のコンソールはアクティブなコードページ次第で描画が変わるためです。
- `--sort <axis>` と `--min-identifier-jaccard <value>` は text 一覧の並べ替えと絞り込みです。[レポートの読み方](reading-a-report.md#並べ替え)を参照してください。
- `--include-vendored` は vendored ツリーの中の重複も報告し、`--include-trivial` は Structural / Semantic モードで predicate family を計測済みの priority に戻します。
- `--no-reuse` は、同一内容の完了済み実行がローカルにあっても解析し直します。
- `--fail-on-findings` は visible finding が残ると exit code 3 を返します。
- `--compare-build-variants` と `--compare-languages` は独立した Semantic comparison を要求し、通常の scan partition を混ぜません。
- `--helper <NAME=PATH>` は helper の場所を `rust=PATH` または `clang=PATH` の形で上書きします。
- `--allow-execution=build-script` は、Semantic helper がプロジェクトの build script を実行するための明示的な opt-in 許可です。これが無ければ scan 対象のコードは実行されず、`--untrusted` でも実行は許可されません。
- `--untrusted` はどのプラットフォームでも scan の上限を下げます。ただし `--mode semantic` と併用する場合は helper プロセスに OS が強制するメモリ上限を要求するため、それを課せる Linux でのみ使えます。ほかの OS では、helper を無防備に走らせる代わりにエラーで停止します。

## `report`

記録済みのスキャン 1 件を、ツリーを読み直さずに再描画します。`scan` が持つ表示系のオプション（形式・詳細度・件数・並べ替え・色・グリフ）をそのまま取るので、text として記録した実行をあとから JSON として書き出せます。`--run <id>` で記録済みスキャンを選びます。どの形式のスキャンも、それを再現する id を表示します。

## `explain`

ローカルデータベースから、グループ 1 つまたは出現箇所 1 つを、安定 ID か一意に定まる prefix で表示します。`--format json` はデータとして出力します。

## `baseline`

`create` は直前に記録されたスキャンの finding をファイルに凍結し、`update` は最新のスキャンが報告しなくなった項目を落とします。どちらもスキャン対象のパスと `--file` を取ります。[baseline](baselines.md) を参照してください。

## `cache`

`status` はローカルデータベースの場所・サイズ・中身を表示します。`prune` は保持上限を適用して圧縮し、既定では単体の artifact 解析を新しい順に 20 件、各種 comparison をそれぞれ 20 件残します（`--keep-artifacts` と `--keep-comparisons` で変更できます）。`clear` はデータベースを恒久的に削除します。`prune` も `clear` も保持済みの履歴を削除するため、どちらも `--force` が必要です。

## `config`

`init` はコメント付きの `codehelion.toml` テンプレートを書き出し、`show` は有効な設定を表示します。[設定](configuration.md)を参照してください。

## `doctor`

このマシンにあるものを報告します。helper とその protocol バージョン、各 helper が問い合わせに答えた内容、プラットフォームが強制できるサンドボックス、このビルドが持つ restricted semantic ルールの数、設定されたディレクトリ内の監査データベースとこのビルドで開けるもの、そしてこのビルドが読める成果物フォーマットです。

## `artifact`

```sh
codehelion artifact analyze path/to/binary
codehelion artifact analyze path/to/binary --format csv  # json も可。既定は text
codehelion artifact analyze path/to/binary --untrusted   # サイズ・時間・メモリの上限を下げる
codehelion artifact analyze path/to/binary --debug-file companion
codehelion artifact report              # 最新の保存済み解析を再描画
codehelion artifact report --analysis 1 # 特定の保存済み解析を再描画
codehelion artifact compare before/binary after/binary
codehelion artifact calibration                 # 記録済みの計測を集計
codehelion artifact calibration --source-run 1  # 特定のソーススキャンを集計
codehelion artifact calibration --baseline earlier.json  # 以前の集計と並べる
```

`--input-format` は magic byte 検出が満たすべきフォーマットを表明し、`--arch` は universal Mach-O のスライスを選びます。`--build-variant`・`--source-run`・`--linker-map` はソース相関のための入力です。[成果物解析](artifact-analysis.md)と [calibration](calibration.md) を参照してください。

## `history`

ローカルのコミット記録だけを読みます。範囲に何件のコミットがあるか、それらが fix / feature / その他のどれに分類されるか、範囲の最初と最後がどのコミットかを出します。ソースファイルは開かず、台帳も読みません。`--path <dir>` でリポジトリを選び、`--until <rev>` で範囲の終端を固定し、`--config <file>` で範囲に関する設定の出所を指定します。`--format text|json`・`--output <file>`・`--force` は他のコマンドと同じ挙動です。

## `seam`

台帳の `[[seam]]` 項目ごとに、非対称変更が何件あったか、そのうち何件が breach になったか、直近の breach がいつだったかを報告します。`--suggest` を付けると、代わりに共変更だけから seam の候補を、各候補の coupling 値と support とともに提示します。台帳へ書き込むことはありません。`--path`・`--config`・`--until`・`--format`・`--output`・`--force` は `history` と同じです。[seam の追跡](seam-tracking.md)を参照してください。

## `guard`

変更 1 つを台帳に照らします。既定では作業ツリーと `HEAD` の差分を読み、`--since <rev>` を付けるとその revision から `HEAD` までの差分を読みます。`--paths <p>...` は編集前に走らせる照会で、指定したパスがどの seam に属し、一緒に動かす必要のあるメンバーがどれかを述べます。台帳だけを読み、git を開きません。

`--deny-asymmetric` は、seam のメンバーの一部だけを触る変更があったときに exit code 3 を返します。付けなければ報告するだけで 0 を返します。実行単位の例外はありません。報告が多すぎる seam は `members` をより細かく切り直します。台帳が無い、または空の場合は何も報告せず 0 を返します。

## 終了コード

- `0`: コマンドは成功しました。
- `1`: 実行上のエラーにより完了できませんでした。
- `2`: コマンドラインの指定が不正です。
- `3`: `scan --fail-on-findings` が 1 件以上の visible finding を検出したか、`guard --deny-asymmetric` が 1 件以上の非対称変更を検出しました。
