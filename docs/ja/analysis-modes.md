# 解析モード

ビルド不要のモードが 2 つと、コンパイラ補助のモードが 1 つあります。モードは実行の identity の一部なので、異なるモードで読んだ結果どうしが比較されることはありません。

![各解析モードが測るもの](../images/modes-ja.svg)

## Fast

トークンレベルで Type-1（完全一致）と Type-2（識別子のリネーム、リテラルの変更）を検出します。比較の前にコメントと空白を除くため、コメントだけの編集でひとつの finding が 2 つに割れることはありません。

Fast が既定なのは、実際の問いに答える最も安価な手段だからです。測れないのは、構文構造を必要とするものすべてです。欠落を伴うコピー、識別子の一致度、類似度の内訳、sibling と near miss が該当します。boilerplate・テストコード・整数幅ファミリの抑制ポリシーもこれらの分類を必要とするため、Fast では適用できず、その旨をレポートに明示します。

そのため、ある程度以上の規模のツリーでは Fast のレポートは有用な長さを超えます。「このファイルはあのファイルのコピーか」を問うときは Fast を、「まず何を見るべきか」を問うときは Structural を使ってください。

## Structural

Structural は Type-3 検出、つまり文の追加・削除・変更を伴うコピーの検出を加え、判定根拠となった次元別の similarity を報告します。構文解析は行いますが、ツリーの中のコードを実行しないことは変わりません。

```sh
codehelion scan --mode structural
```

レポートを並べ替えて読めるようにするのが Structural です。canonical member に対する識別子の一致度を測り、2 つの出現箇所が「どのように」似ているかを述べる類似度の内訳を出し、[グループ化](grouping.md)で説明する 2 つの sibling channel と near miss の帯を動かします。抑制ポリシーもここで適用され、生成コード・テストのフィクスチャ・整数幅ごとに 1 本ずつ書かれた関数群が、読む価値のある finding を押しのけないようにします。

代償はセットアップではなく時間とメモリです。ビルドもツールチェーンも不要で、バイナリ以外に導入するものはありません。

## Semantic

> **1.0 前の面です。** 文書化もテストもされていますが、約束に値するだけの実利用を経ていないため、リリース間で変わり得ます。

Semantic は、Structural が測るものすべてに加えて、コンパイラが解決した型と名前の情報、および登録済みの semantic ルールを加えます。

```sh
codehelion scan --mode semantic
```

解析対象の言語ごとに helper が必要です。Rust なら `codehelion-backend-rust`、C / C++ なら `codehelion-backend-clang` を `PATH` に置くか `--helper` で指定します。`codehelion doctor` が、どれが存在するか、各 helper が話す protocol のバージョン、見つけたコンパイラ、供給できると言っている情報を報告します。helper の無い言語は実行を失敗させず、Structural として解析します。

helper はバージョン付き protocol で通信する別プロセスなので、compiler API が CLI にリンクされることはありません。コンパイラがクラッシュしても終わるのは helper プロセスで、スキャンは該当ユニットを unavailable として記録し継続します。[アーキテクチャ](architecture.md)を参照してください。

Semantic も、実行分類を明示的に許可しないかぎりプロジェクトのコードを実行しません。

```sh
codehelion scan --mode semantic --allow-execution=build-script
```

このフラグが無ければツリーの中のコードは実行されず、`--untrusted` では実行を一切許可しません。[ローカル実行と信頼](security.md)を参照してください。

Semantic 限定の opt-in な比較が 2 つあります。`--compare-build-variants` は異なる C/C++ build variant のあいだで完全一致の unit を比較し、`--compare-languages` は明示的に選んだ compilation partition をまたいで Rust と C++ の登録済みパイプラインを比較します。どちらも独立した comparison を出力し、通常の scan partition を混ぜることはありません。

## 選び方

| 問い | モード |
|---|---|
| このファイルはあのファイルのコピーか | Fast |
| ある程度の規模のツリーで、まず何を見るべきか | Structural |
| 終えたばかりのリファクタで呼び出し元を取り逃していないか | Structural |
| コンパイラが名前を解決したあとで、この 2 つは同じルーチンか | Semantic |

そのモードで測れない次元は推測せず「測定なし」として報告するため、レポートは常に、この問いのどれに答えられたかを示します。
