# codehelion

[![CI](https://img.shields.io/github/actions/workflow/status/libraz/codehelion/ci.yml?branch=main&label=CI)](https://github.com/libraz/codehelion/actions)
[![crates.io](https://img.shields.io/crates/v/codehelion.svg)](https://crates.io/crates/codehelion)
[![codecov](https://codecov.io/gh/libraz/codehelion/branch/main/graph/badge.svg)](https://codecov.io/gh/libraz/codehelion)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](https://github.com/libraz/codehelion/blob/main/LICENSE)
[![Rust](https://img.shields.io/badge/Rust-1.98%2B-orange?logo=rust)](https://www.rust-lang.org)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey)](https://github.com/libraz/codehelion)

**codehelion は、Rust / C / C++ の重複ロジックを検出し、スキャンをまたいで同じ重複を追い続けるツールです。** ソースをそのまま読むので、ビルドもコンパイルデータベースもネットワークも要りません。各 finding には内容から導いた識別子が付くため、ある重複について下した判断は、無関係な編集をはさんでもその重複に付いたまま残ります。何もマシンの外に出ず、読んだコードを実行することもありません。

**こんなときに使えます:**

- **簡単にはビルドできないツリーを調べたい** — Rust / C / C++ の混在、vendor されたコード、移植の途中でも、エラー耐性のある lexer 1 つでコンパイラなしに読めます。
- **数か月かけて重複を減らしたい** — 出発点を baseline に記録し、残すと決めたものを抑制しておけば、以降のスキャンで増えたものが分かります。
- **CI で新しいコピーを止めたい** — パーセンテージではなく、baseline に無い重複が現れたときに失敗させられます。SARIF は code scanning のビューに載せられます。
- **対になったファイルを揃えておきたい** — 2 つのフロントエンドや en/ja の文書の組を seam として宣言すると、片側だけに触れた変更を `guard` が報告します。
- **バイナリや WASM が大きくなった理由を知りたい** — コードのバイトを自分のコードと toolchain に分け、テンプレートの本体を name stem ごとに集計し、2 つのビルドを比較できます。

📖 **[ドキュメント](https://github.com/libraz/codehelion/blob/main/docs/ja/introduction.md)** &nbsp;·&nbsp; **[はじめかた](https://github.com/libraz/codehelion/blob/main/docs/ja/getting-started.md)** &nbsp;·&nbsp; **[制限](https://github.com/libraz/codehelion/blob/main/docs/ja/limitations.md)**

> codehelion は 1.0 前です。Fast / Structural のスキャン、text と JSON のレポート、`artifact analyze` は固まっていて、それ以外はリリース間で変わり得ます（[成熟度](https://github.com/libraz/codehelion/blob/main/docs/ja/introduction.md#成熟度)）。セキュリティ上の問題は [SECURITY.md](https://github.com/libraz/codehelion/blob/main/SECURITY.md) の手順で報告してください。

## レポートの見え方

codehelion 自身のツリーに対する Structural モードの実行結果です（先頭 2 グループ）。

```text
codehelion scan · structural mode · ~/src/codehelion

 #1  0.56  type-1 ×2      109 tokens  64f5bc34
     ├─ ◆ corpus/synthetic/rust/seed.rs:30-49                   values_equal
     └─   corpus/synthetic/rust/type1.rs:35-54                  values_equal

 #2  0.54  type-1 run ×2  106 tokens  53c92308
     ├─ ◆ crates/codehelion-cli/src/scan/structural.rs:159-171  run_with
     └─   crates/codehelion-cli/src/scan.rs:61-73               run

... and 1305 more groups (--limit 0 lists every one)

seams: frontend-c-cpp 12 asymmetric changes, 7 breaches (last 6e014d86), 394 findings
       readme-en-ja 1 asymmetric change, 1 breach (last 634aa5c9)
       artifact-fixture-scripts 3 asymmetric changes, 1 breach (last 6f5d63c3)

1,702 groups (type-1 85, type-2 204, type-3 1413) · 395 suppressed · sorted by priority
supplemental: 556 siblings (--show-siblings; 116 dropped by search ceilings), 1,000 near misses (--show-near-misses; 6,746 dropped by the retention cap)
569 files, 220,783 lines, 1,167,009 tokens · run 12 (replay: codehelion report --run 12)
◆ the occurrence a group is measured against · "run" a repeated stretch of statements, not a whole unit · ×N the number of occurrences
open one: codehelion explain 64f5bc34 · list every group: --limit 0
```

各フィールドの意味は[レポートの読み方](https://github.com/libraz/codehelion/blob/main/docs/ja/reading-a-report.md)にあります。

## できること

- **ビルド不要のスキャン** — エラー耐性のある lexer が Rust / C / C++ を直接読むため、言語が混在するツリーも一度に、同じ基準で走査できます。Semantic モードは別プロセスの helper からコンパイラ由来の情報を加えます。[解析モード](https://github.com/libraz/codehelion/blob/main/docs/ja/analysis-modes.md)
- **安定した finding ID** — 行番号ではなく内容の fingerprint で名前を付けるので、同じ入力からは同じ ID が同じ順序で出て、抑制と baseline がリファクタリングをまたいで保たれます。[安定した識別子](https://github.com/libraz/codehelion/blob/main/docs/ja/stable-ids.md) · [baseline](https://github.com/libraz/codehelion/blob/main/docs/ja/baselines.md) · [抑制](https://github.com/libraz/codehelion/blob/main/docs/ja/suppression.md)
- **単一スコアではなく根拠** — lexical / structural / control-flow / type / API の similarity を別々に報告し、そのモードで測れない指標は測定なしとして示します。[レポートの読み方](https://github.com/libraz/codehelion/blob/main/docs/ja/reading-a-report.md) · [クローンの型](https://github.com/libraz/codehelion/blob/main/docs/ja/clone-types.md)
- **順序付けたレポート** — 実プロジェクト 8 件のラベル付きスナップショットで、上位 10 件に誤りが 1 つも入りません（p@10 1.0000、MAP 0.9290）。端から端まで読むと適合率は 0.5920 です。[精度](https://github.com/libraz/codehelion/blob/main/docs/ja/accuracy.md)
- **seam と CI のゲート** — 一緒に変えるべきファイルを `guard` が確かめ、`scan --fail-on-findings` は変更が増やした重複でゲートします。[seam の追跡](https://github.com/libraz/codehelion/blob/main/docs/ja/seam-tracking.md) · [継続的インテグレーション](https://github.com/libraz/codehelion/blob/main/docs/ja/continuous-integration.md)
- **成果物のサイズ** — WASM / ELF / Mach-O / PE/COFF を実行せずに読み、所有者別のコードのバイト、toolchain のコードをリンクに残している関数、name stem、圧縮後サイズ、2 つのビルドの比較を出します。[成果物解析](https://github.com/libraz/codehelion/blob/main/docs/ja/artifact-analysis.md)
- **構造としてのローカル実行** — ネットワークを使わず対象ツリーを実行しないことを lint と依存ポリシーで強制し、発火したリソース上限はすべてレポートに計上します。[ローカル実行と信頼](https://github.com/libraz/codehelion/blob/main/docs/ja/security.md)

## インストール

各[リリース](https://github.com/libraz/codehelion/releases)に、SQLite を同梱した自己完結の `codehelion` バイナリと `SHA256SUMS` が添付されます。

| プラットフォーム | アーカイブ |
|---|---|
| Linux x86-64 | `codehelion-<version>-linux-x86_64.tar.gz` |
| Linux ARM64 | `codehelion-<version>-linux-aarch64.tar.gz` |
| macOS Apple silicon | `codehelion-<version>-macos-aarch64.tar.gz` |
| Windows x86-64 | `codehelion-<version>-windows-x86_64.zip` |

```bash
cargo install codehelion   # ソースからビルドする場合。Rust 1.98 以降が必要
```

Semantic モードでは言語ごとの helper も必要です。helper と `codehelion doctor` は[はじめかた](https://github.com/libraz/codehelion/blob/main/docs/ja/getting-started.md)にあります。

## クイックスタート

```bash
codehelion scan --mode structural     # ツリーを読み、重複を報告する
codehelion explain 64f5bc34           # グループを 1 つ開く
codehelion artifact analyze app.wasm  # ビルドのバイトがどこに行っているか
```

→ [はじめかた](https://github.com/libraz/codehelion/blob/main/docs/ja/getting-started.md) · [コマンドライン](https://github.com/libraz/codehelion/blob/main/docs/ja/cli.md)

## ソースからビルド

```bash
make check   # format-check + lint + 境界検査 + test + doc
make eval    # コーパスに対する検出精度
```

残りは `make help` にあります。規約とガードレールは [CONTRIBUTING.md](https://github.com/libraz/codehelion/blob/main/CONTRIBUTING.md) にあります。

## ドキュメント

- **学ぶ** — [はじめに](https://github.com/libraz/codehelion/blob/main/docs/ja/introduction.md) · [はじめかた](https://github.com/libraz/codehelion/blob/main/docs/ja/getting-started.md) · [解析モード](https://github.com/libraz/codehelion/blob/main/docs/ja/analysis-modes.md) · [用語集](https://github.com/libraz/codehelion/blob/main/docs/ja/glossary.md)
- **出力を読む** — [レポートの読み方](https://github.com/libraz/codehelion/blob/main/docs/ja/reading-a-report.md) · [クローンの型](https://github.com/libraz/codehelion/blob/main/docs/ja/clone-types.md) · [グループ化](https://github.com/libraz/codehelion/blob/main/docs/ja/grouping.md) · [安定した識別子](https://github.com/libraz/codehelion/blob/main/docs/ja/stable-ids.md)
- **プロジェクトで使う** — [リファクタのループ](https://github.com/libraz/codehelion/blob/main/docs/ja/refactoring-workflow.md) · [baseline](https://github.com/libraz/codehelion/blob/main/docs/ja/baselines.md) · [抑制](https://github.com/libraz/codehelion/blob/main/docs/ja/suppression.md) · [設定](https://github.com/libraz/codehelion/blob/main/docs/ja/configuration.md) · [seam の追跡](https://github.com/libraz/codehelion/blob/main/docs/ja/seam-tracking.md) · [継続的インテグレーション](https://github.com/libraz/codehelion/blob/main/docs/ja/continuous-integration.md) · [コマンドライン](https://github.com/libraz/codehelion/blob/main/docs/ja/cli.md)
- **成果物** — [成果物解析](https://github.com/libraz/codehelion/blob/main/docs/ja/artifact-analysis.md) · [calibration](https://github.com/libraz/codehelion/blob/main/docs/ja/calibration.md)
- **詳細** — [制限](https://github.com/libraz/codehelion/blob/main/docs/ja/limitations.md) · [精度](https://github.com/libraz/codehelion/blob/main/docs/ja/accuracy.md) · [ローカル実行と信頼](https://github.com/libraz/codehelion/blob/main/docs/ja/security.md) · [アーキテクチャ](https://github.com/libraz/codehelion/blob/main/docs/ja/architecture.md)

## 含まないもの（Non-goals）

codehelion が測るのは保守性であってサイズではありません。報告されたクローンを消しても、ビルドした成果物が小さくなるとは限りません。すべてのコピーを見つけること、意味的な等価性の証明、コーディング規約や脆弱性の検査、自動リファクタリングは対象外で、GUI やホスト型サービスもありません。詳しくは[制限](https://github.com/libraz/codehelion/blob/main/docs/ja/limitations.md)を参照してください。

## ライセンス

[Apache-2.0](https://github.com/libraz/codehelion/blob/main/LICENSE)
