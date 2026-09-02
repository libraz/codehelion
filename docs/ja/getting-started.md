# はじめかた

## インストール

```sh
cargo install codehelion
```

生成されるのは `codehelion` という自己完結の単一バイナリで、SQLite は同梱されています。チェックアウトからビルドする場合は次のとおりです。

```sh
cargo install --path crates/codehelion-cli
```

任意の Rust Semantic helper を含め、すべて Rust 1.98 以降が必要です。この下限は helper が使う解析ライブラリが決めており、コンポーネントごとに分かれてはいません。

## 最初のスキャン

```sh
codehelion scan
```

引数を付けなければ、カレントディレクトリを Fast モードで読み、text レポートを出力します。ある程度以上の規模のツリーでは Structural モードを使ってください。欠落を伴うコピーを検出でき、抑制ポリシーが働くため、上から読んでいける一覧になります。

```sh
codehelion scan --mode structural
```

レポートは何を読んだかで始まり、上位のグループを列挙し、合計で終わります。

```text
codehelion scan · structural mode · ~/src/project

 #1  0.56  type-1 ×2      109 tokens  b92c1297
     ├─ ◆ corpus/synthetic/rust/seed.rs:30-49                   values_equal
     └─   corpus/synthetic/rust/type1.rs:35-54                  values_equal

 #2  0.53  type-1 run ×2  101 tokens  5d7e5cd2
     ├─ ◆ crates/codehelion-cli/src/scan/structural.rs:205-211  run_with
     └─   crates/codehelion-cli/src/scan.rs:70-76               run

... and 1185 more groups (--limit 0 lists every one)

1,539 groups (type-1 78, type-2 199, type-3 1262) · 352 suppressed · sorted by priority
supplemental: 493 siblings (--show-siblings; 60 dropped by search ceilings), 1,000 near misses (--show-near-misses; 5,624 dropped by the retention cap)
552 files, 199,199 lines, 1,040,264 tokens · run 6 (209 file(s) changed; replay: codehelion report --run 6)
◆ the occurrence a group is measured against · "run" a repeated stretch of statements, not a whole unit · ×N the number of occurrences
open one: codehelion explain b92c1297 · list every group: --limit 0
```

見出しの各フィールドの意味は[レポートの読み方](reading-a-report.md)にあります。末尾の短い 16 進文字列がグループの安定 ID で、これは `codehelion explain` が受け付ける最短の prefix です。

```sh
codehelion explain b92c1297
```

上限の発火や何にも一致しなかったルールなど、実行そのものを限定する情報は標準エラー出力に回るため、標準出力のレポートはパイプに流せる状態を保ちます。

## 結果が置かれる場所

各スキャンは、scan root を含む Git リポジトリ直下の `.codehelion/` にローカルの SQLite データベースを作って記録します。サブディレクトリをスキャンしたときも新しいデータベースを作らず、リポジトリのものを使い続けます。リポジトリの `.gitignore` に `.codehelion/` を追加してください。

実行が記録されているため、ツリーを読み直さずにレポートを描き直せます。

```sh
codehelion report                    # 最新の完了済みスキャンを再描画
codehelion report --run 1            # 特定の記録済みスキャンを再描画
codehelion report --format json --output report.json
```

データベースの場所と扱いは[設定](configuration.md)に、コマンドとフラグの一覧は[コマンドライン](cli.md)にあります。

## 任意: コンパイラ由来の情報

Semantic モードはコンパイラが解決した型と名前の情報を加えます。解析したい言語ごとに別途 helper を導入する必要があり、これが compiler API を CLI 自体から締め出しています。

```sh
cargo install codehelion-backend-rust
cargo install codehelion-backend-clang # システムの libclang も必要
codehelion doctor
```

`doctor` は、このマシンにあるコンポーネント、各 helper が問い合わせに何を答えたか、実行が使うローカルデータベースはどれかを報告します。導入されていない helper は「任意で、いまは無い」として報告され、それによって失敗することはありません。

## 任意: 成果物解析

`artifact` コマンドは、コンパイル済み成果物（WASM・ELF・Mach-O・PE/COFF・静的アーカイブ）のバイト列を、ロードも実行もせずに読みます。

```sh
codehelion artifact analyze path/to/binary
```

ソーススキャンはこれに一切依存しません。[成果物解析](artifact-analysis.md)を参照してください。

## 次に読むもの

- [解析モード](analysis-modes.md) — Fast / Structural / Semantic の選び方。
- [リファクタのループ](refactoring-workflow.md) — 最初のレポートをどう使うか。
- [抑制](suppression.md) — 残すと決めたものを静かにする。
