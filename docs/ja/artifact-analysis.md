# 成果物解析

`artifact` コマンドはコンパイル済み成果物をローカルで読みます。読むのはバイト列だけで、対象の成果物をロードすることも実行することもありません。ソーススキャンはこれに一切依存しません。クローンエンジンは成果物リーダーに依存しておらず、成果物がひとつも無くてもソーススキャンは完全に成立します。

```sh
codehelion artifact analyze path/to/binary
codehelion artifact analyze path/to/binary --format csv  # json も可。既定は text
codehelion artifact report              # 最新の保存済み解析を再描画
codehelion artifact compare before/binary after/binary
```

## フォーマットごとに確立できること

![成果物のフォーマットごとに確立できること](../images/artifact-ja.svg)

観測済みサイズと重複したコードは、どのフォーマットについても報告します。それ以外は、そのフォーマット自身が確立できる量に限られます。retained size と shared size はコールグラフを必要とし、これを導けるのは WASM、ELF、静的アーカイブです。重複データは独立にサイズの付くデータ領域を必要とし、それを持つのは WASM です。ソース位置にはデバッグ情報が要ります。ELF なら DWARF、Mach-O なら identity の一致する dSYM、PE/COFF なら一致する PDB、WASM なら記録された source map の URL です。

フォーマットが供給できない量は数値を作らず unavailable として報告し、何が足りなかったかを述べる assumption を並べます。

静的アーカイブと再配置可能オブジェクトは、シンボル全体にだけ帰属させ、ソースの行範囲は持ちません。再配置可能オブジェクトには行テーブルを結びつけるロードアドレスが無いためです。メンバーをリンクしてイメージにすると、行範囲に届きます。

ELF の retained size とデッドコードの候補は、直接の呼び出しに加えて、関数の外へ出るジャンプ（末尾呼び出し）と、アドレスが取られている関数をたどります。後者は呼び出し辺が届かなくても実行されるためです。レジスタやメモリスロット経由のジャンプや呼び出しは、リーダーが名指しできない呼び出し先に届くので、それが現れる場合のデッドコード一覧は証明ではなく候補の一覧です。

フォーマットごとの能力表は、各バックエンドが自ら返す定義から生成されており、`crates/codehelion-artifact/FORMAT_SUPPORT.md` にあります。

### WebAssembly のソース対応はシンボル単位まで

ELF・Mach-O・PE/COFF は DWARF、identity の一致する dSYM、一致する PDB を通じてソース行に到達でき、クローングループの行範囲にバイトを帰属させられるのはこのソース行があるからです。コアモジュールが持つのは name セクションの関数名だけで行情報が無いため、対応づけは関数単位までにとどまり、クローングループの byte 帰属は unavailable になります。DWARF を出してビルドすれば行情報は得られますが、それは測っている対象そのもの — 通常はそれこそが検査の理由であるサイズ — を変えてしまいます。そのため各レポートは、別の問いに答えるビルドを要求するのではなく、name セクションで何が得られて何が得られないかを述べます。

## デバッグ情報

デバッグ情報は ELF build ID、Mach-O UUID、または PE CodeView/PDB identity が一致した場合にだけ受け入れます。identity を確かめないまま受け入れると、あるビルドのバイトを別のビルドのソースに帰属させてしまうからです。

```sh
codehelion artifact analyze path/to/binary --debug-file companion
```

これは source scan なしでも使えます。source-artifact correlation を要求する場合にだけ `--source-run` と `--build-variant` を追加してください。

## build variant

`--build-variant` に渡すのは自分で書くファイルで、どこかにある既存のファイルを探すものではありません。中身は自由に決められます。それによって得られるのは、同じ条件でビルドされた成果物どうしだけが比較される、という保証です。

```sh
echo '{"profile":"release","target":"wasm32","toolchain":"emcc-5.0.2"}' > build-variant.json
codehelion artifact analyze dist/app.wasm --build-variant build-variant.json --source-run 2
```

`--build-variant manifest.json` を渡した場合、build variant の identity には正規化した JSON 値を使うため、空白や object member の順序は identity を変えません。

source run にも build variant があり、JSON と SARIF のレポートはその digest を持ち、text のレポートは成果物の削減見積もりの隣にだけ表示します。両者は別々の条件 — ソースをどう読んだか、成果物をどうビルドしたか — であり、突き合わせるのではなく並べて記録します。manifest に書き写すべき source 側の digest は存在しません。

## 実体化の多重度

「ソース上に写しが何個あるか」と「バイナリ上に本体が何個あるか」は別の軸で、codehelion の探索モデルにあるのは前者だけです。ソース上は 1 本のテンプレートでも、呼び出し箇所ごとにクロージャ型や型引数が違えば、成果物上では十数個の別々の実体になります。ソース上の写しは 1 つなので、この多重度を述べるクローングループは存在しません。

ソーススキャンと相関させた場合は別立てで報告します。

```sh
codehelion artifact analyze path/to/binary --source-run 1 --build-variant build-variant.json
```

これは、成果物が複数の実体として出力したソース単位を、実体の個数と観測サイズとともに並べます。ここに出るバイト数は成果物が現に費やしている量であって削減量ではありません。ソース上の 1 本を統合しても実体は 1 つも減らず、この数値を下げるには実体化の回数そのものを減らすことになります。数えるのに必要なのは「マッピングが単一のソース単位を指したこと」だけなので、シンボル名さえあれば足り、デバッグ行情報は要りません。

## コードの所有者

> **1.0 前の面です。** 文書化もテストもされていますが、約束に値するだけの実利用を経ていないため、リリース間で変わり得ます。

`artifact analyze` は、報告するシンボルのコードバイトを所有者ごとに分け、toolchain のコードを成果物に残している非 toolchain の関数を名指しします。どちらもシンボル名だけを読むので、名前さえあればどのフォーマットでもどの言語でも使えます。holder の表示にはさらにコールグラフと retained size が必要です（[フォーマットごとに確立できること](#フォーマットごとに確立できること)を参照）。

シンボルの owner（所有者）は、定義パスの先頭要素です。Rust ならクレート、C++ ならトップレベルの名前空間、修飾のない名前なら `<global>` です。owner は次のいずれかの class に入ります。

- `toolchain` — Rust の sysroot クレート、C++ の `std` とグローバルなアロケーション演算子、C17 Annex B の関数、C17 が実装に予約している識別子、ランタイムサポート。
- `own` — `[artifact] own` に列挙した owner。[設定](configuration.md#artifact)を参照。
- `other` — 名前はあるが上のどちらでもない owner。サードパーティのクレートなど。
- `unnamed` — 名前のない関数。owner を割り当てられません。

toolchain の分類は宣言に左右されません。`own` が空のあいだ、toolchain の外にある名前付きのコードは `other` として報告され、レポートもそう述べます。

`strtof(s, 0)` を返すだけの C 関数 `parse` を emscripten の `-O1` でビルドし、`own = ["<global>"]` で解析すると次のようになります。

```
ownership: own 6768 bytes (5 symbols), toolchain 10629 bytes (35 symbols), other 0 bytes (0 symbols), unnamed 0 bytes (0 symbols)
  declared own: <global>
  reserved (toolchain, reserved): 9013 bytes, 25 symbols
  <global> (own): 6768 bytes, 5 symbols
  c-std (toolchain, c_std): 1540 bytes, 6 symbols
  runtime (toolchain, runtime): 76 bytes, 4 symbols
  outside symbols: 61 bytes
  assumption: ownership follows the defining path of each symbol name, so generic code instantiated for your types is counted under the library that defines it
toolchain holders (held bytes are part of the holder's retained size):
  parse (own) f31665862c71112cfffda8f55fc54dd2: 17307 bytes in 34 symbols, 6756 bytes in 4 symbols absorbed
    head strtof 320251c57384d307522b489a48cc4e39: 17307 bytes
  shared: 78 bytes in 5 symbols, 0 bytes in 0 symbols absorbed
    setThrew ba286dbdc84dc40e5966ae8f29485879: 38 bytes (root), called by nothing
    _initialize 4feb66b59715a8dcbf2af30ae02ec5d6: 20 bytes (root), called by nothing
    _emscripten_stack_restore ef2222560055353cb931a59336cb3e00: 10 bytes (root), called by nothing
    emscripten_stack_get_current 4eaae22504bd0bae04ab33f12aeef742: 8 bytes (root), called by nothing
    __wasm_call_ctors a0d352ddbe45c0d90cb9d358e3fa1f9d: 2 bytes (root), called by _initialize (toolchain)
  assumption: unqualified functions whose immediate dominator is toolchain code are counted as toolchain code, except main and static initializers
  assumption: toolchain holders treat every recorded function reference as a root, so code reached through a function table is reported as shared
```

`outside symbols` は実行可能セクションのサイズからシンボルのサイズの合計を引いた残りで、これを足すとセクション全体に一致します。text 出力に並ぶのはバイト数の大きい上位 10 owner までで、JSON には全件が入ります。`artifact compare` もバイト差を同じように分けます。シンボルは after 側の owner に、削除されたものは before 側の owner に帰属させ、割り振れない残りは `outside symbols` として示します。

holder は、toolchain のコードではないのに toolchain のコードを成果物に残している関数です。そのコードは holder を通してしか到達できません。toolchain の各関数は、コールグラフ上でいちばん近い非 toolchain の支配元に帰属します。holder の直下で直接入る toolchain 関数が head で、holder の行にはその下にあるものすべてのバイト数が入ります。直近の支配元が toolchain のコードである修飾なしの関数は、toolchain のコードとして数えるため、libc の補助関数が自分の呼ぶ libc を抱えているようには見えません。この分は absorbed として別に示します。`main` と静的初期化子は吸収しません。

held bytes は holder の retained size の一部です。toolchain のコードがどこから入っているか、その入口を外すと何が切り離されるかを示すもので、削減の保証ではありません。次のビルドでは同じコードに別の経路から届くこともあります。

非 toolchain の関数がひとつも支配していない toolchain のコードは shared toolchain code です。合計を出し、入口ごとにそれを直接呼ぶ関数を挙げます。成果物がエクスポートしている入口には `(root)` が付きます。shared のバイトはどの holder にも属さず、呼び出し元の間で按分もしません。holder は retained size が出ないときは出ず、レポートは数値の代わりにその旨を述べます。名前だけで所有者を決めることの限界は[制限](limitations.md#成果物検査はシンボルに依存します)にあります。

owner のラベルはレポートを描画するたびに、保存済みのシンボル名と現在の `[artifact] own` から導きます。所有者に関するものはデータベースに書き込みません。そのため `artifact report` は実行時点の設定に従い、`artifact compare` も `artifact analyze` と同じく作業ディレクトリの設定を読みます。

## 同一関数のコピー

静的リンクされたビルドの libc 関数のように、1 つの成果物の中に名前と本体が同じ関数が複数ある場合があります。各コピーは自分の fingerprint を持つので、サイズも呼び出しグラフ上の位置もコピーごとに別です。共有される内容は JSON レポートの `content_fingerprint` が示します。呼び出し元、呼び出し先、ルート、サイズ、本体のいずれでも他のコピーと区別できないコピーはファイル内の順序で見分けられ、`identity_by_order` が付きます。`artifact compare` はコピーを fingerprint ではなく内容で対応づけます。アーカイブ内のシンボルも、メンバー全体のバイト列に依存しない `content_fingerprint` を持ちます。1 つの関数を変更しても、同じメンバー内のほかの関数の比較用識別子は変わりません。

## 名前の stem

1 つの成果物の中に、テンプレート引数、クロージャの番号、引数リストだけが違う本体が複数あることがあります。`int probe<f::$_0>(char const*, f::$_0)`、`int probe<f::$_1>(char const*, f::$_1)`、`int probe<f::$_2>(char const*, f::$_2)` は 1 つのテンプレートの 3 つの本体です。name stem は、名前を最初の「パラメータ化された要素」で切ったものです。テンプレート引数は `<>`、クロージャは `{closure}` と書き、引数リストと戻り値型は含みません。上の 3 つの本体は stem `probe<>` を共有し、それぞれの綴りは instance として残ります。

切るのは名前の末尾ではなく最初のパラメータ化された要素なので、1 つのコンテナのメンバーはどのメソッドでも同じ stem になります。`std::__2::deque<int>::push_back(int&&)` と `std::__2::deque<int>::pop_front()` はどちらも `std::__2::deque<>` に属し、サイズはそのコンテナにかかるバイト数として合算されます。パラメータ化された要素を持たない `solo()` のような名前は stem `solo` になり、オーバーロード（`foo(int)` と `foo(unsigned int)`）は 1 つの stem を共有します。

`artifact analyze` は、本体が 2 つ以上ある stem を、シンボル名だけから並べます。source run は要りません。

```text
name stems emitted as several bodies (observed, not savings):
  probe<> (other): 3 bodies in 3 instances, 948 bytes
```

各行には owner の分類、本体の数、異なる instance の数、本体のサイズの合計が出ます。`--verbose` を付けると、各行の下に instance ごとの行が加わります。

```text
    probe<f::$_2>: 1 bodies, 340 bytes
```

上位 10 行を列挙し、残りは件数だけを示します。JSON レポートでは `name_stems`、CSV では `name-stem` と `name-stem-instance` のレコードです。

これは観測したバイト数であって削減量ではありません。ソース上で 1 度だけ書かれたテンプレートが、ある stem の本体をすべて生み出していることもあるため、この値は成果物が現に費やしている量であり、ソースを統合したときに減る量ではありません。束ね方は stem の完全一致であり、類似度ではありません。したがって[グループ化](grouping.md)の非推移性に関する考慮はここには及びません。同内容のコピーは、完全一致の重複グループと、本体が複数で instance が 1 つの stem の両方に現れます。2 つは同じバイトを別の側から述べています。

本体が 2 つ以上ある stem が 1 つもなければ、この節は出ません。シンボルに名前がない成果物でも同じです。節が無いことだけでは、strip された成果物なのか、名前の重複が無い成果物なのかは区別できません。名前のないシンボルは ownership の節が報告します。

## 圧縮後のサイズ

```sh
codehelion artifact analyze path/to/binary --compressed gzip --compressed brotli
```

は、入力全体をアルゴリズムごとに 1 回測り、1 つにつき 1 行を出します。

```text
compressed bytes (gzip, level 9, flate2 (miniz_oxide)): 209710
```

値は圧縮ストリーム全体の長さです。gzip は `flate2` の `miniz_oxide` バックエンドで level 9 を使い、ヘッダのタイムスタンプは 0、ファイル名は含みません。brotli は quality 11、ウィンドウ 22 ビットです。このフラグは任意で、繰り返して指定できます。指定しなければ圧縮は走らず、行も JSON の項目も CSV のレコードも出ません。JSON レポートでは `compressed_sizes`、CSV では `compressed-size` のレコードです。`artifact report` は解析時に記録した値を表示し、成果物を読み直しません。

この値は、シンボル・stem・owner・重複グループには割り付けません。圧縮器が 1 つの関数に対して出す出力は、その手前に何があるかに依存します。関数を並べ替えるだけで、どの関数も変えなくても値は動き、部分ごとに計算した値を足しても全体になりません。レポートは値の隣でこのことを述べます。

エンコーダーは外部のツールそのものではありません。同じレベルの外部圧縮器とは数分の一パーセント程度の差が出るので、`gzip -9` の値とここに出る値を並べて比べることはできません。比較は 1 回の `artifact compare` の中で行ってください。両側を同じエンコーダーで測ります。

brotli の quality 11 は gzip よりずっと遅く、この測定は `--timeout-seconds` の中で実行されます。この間にタイムアウトすると `compression` フェーズが示されます。上限を上げるか、gzip だけにしてください。

## 2 つのビルドを比較する

> **1.0 前の面です。** 文書化もテストもされていますが、約束に値するだけの実利用を経ていないため、リリース間で変わり得ます。

```sh
codehelion artifact compare before/binary after/binary
```

は、同じフォーマットの成果物 2 つのあいだで実測したバイト差を報告します。両方の build variant manifest を渡せば、ビルド条件が違う場合に警告を出し、差がソース変更だけから来たかのように見せることはしません。バイトが変わったのにサイズが変わらないネイティブのシンボルは modified として報告します。バックエンドがオペランドをデコードせず本体の identity を持たない場合は、保持しているコードのバイト列がその代わりになります。さらに source run とクローングループを渡すと、calibration の計測も記録します。[calibration](calibration.md) を参照してください。

`--compressed gzip`（または `brotli`）を付けると、比較は両方の成果物を同じプロセスで測ります。両側が同じエンコーダーと設定になり、他のバイト差の隣に差を出します。

```text
compressed bytes (gzip, level 9, flate2 (miniz_oxide)): 209828 before, 209710 after, -118 bytes (smaller)
```

JSON では `compressed_deltas`、CSV では `compressed-delta` のレコードです。圧縮後の差が出るのは、両側を同じアルゴリズムと設定で測ったときだけです。

シンボルの差は内容でシンボルを対応づけるので、シグネチャが `foo(int)` から `foo(unsigned int)` に変わり、本体も違う関数は、削除された 1 つと追加された 1 つとして現れます。stem delta はこれを stem `foo` の下で合算します。本体の数も数えるので、3 つの実体が 1 つになったテンプレートは次のように出ます。

```text
stem delta:
  probe<> (other): 3 -> 1 bodies, -608 bytes
```

行が出るのは、シンボル差のうち 2 つ以上が stem を共有するとき、または stem の本体数が変わっていずれかの側に 2 つ以上あるときです。本体数は変更されたシンボルだけでなく、各成果物の全体で数えます。バイト差はシンボル差の合計です。該当する行がなければこの節は出ません。JSON では `stem_deltas`、CSV では `stem-delta` のレコードです。

両方の成果物がアーキテクチャを記録していて、その 2 つが異なる場合は、比較のどの出力形式でもそのことを述べます。フォーマットやアーキテクチャの異なる成果物どうし、およびユニバーサル Mach-O から選んだアーキテクチャについては、calibration の記録そのものを拒否します。後者の観測バイト数はコンテナ全体を数えているからです。

## 上限と隔離

`artifact analyze` と `artifact compare` は既定で 512 MiB を超える入力を拒否し、parse・相関・永続化・render を別プロセスの worker で行い、全体に 30 秒の期限を適用します。worker が別プロセスであるため、壊れた入力によってパーサが進まなくなっても期限は有効で、timeout の診断は停止した段階を名指しします。

- `--max-bytes` と `--timeout-seconds` が入力サイズと時間の上限を調整します。入力の上限は、DWARF と PDB のデバッグ情報がフレームや行レコードへ展開される範囲も制限します。
- `--max-memory-bytes <bytes>` は Linux で worker の仮想メモリ上限を強制します。ほかの OS ではこのオプションを黙って無視せず、エラーとして返します。
- `--untrusted` はこの 3 つをまとめて締めるため Linux 限定です。ほかの OS では、強制できないメモリ上限のまま素性の分からない成果物を読む代わりにエラーで停止します。

`artifact report` と `artifact calibration` はローカルデータベースにあるものを読み直すだけで、worker を挟まずプロセス内で動くため、これらのオプションは対象外です。`artifact report` 用に保存する versioned IR には別途 64 MiB の上限があります。IR には code と data の生のバイトが含まれるため、入力上限を大きく下回るバイナリでもこれを超えることがあります。その場合 `artifact analyze` は analysis id なしでレポートを出力し、分析を保存しなかった旨を警告し、データベースにはレコードを書きません。

## 結果の読み方

これらのコマンドが測るのはビルドされた成果物そのものです。ソース側で重複を統合したら成果物から何が減るかを予測するものではなく、両者の隔たりは無視できません。サイズの数値をリファクタの根拠に使う前に[制限](limitations.md)を読んでください。
