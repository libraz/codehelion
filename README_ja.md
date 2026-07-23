# codehelion

[![CI](https://github.com/libraz/codehelion/actions/workflows/ci.yml/badge.svg)](https://github.com/libraz/codehelion/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/codehelion.svg)](https://crates.io/crates/codehelion)
[![codecov](https://codecov.io/gh/libraz/codehelion/branch/main/graph/badge.svg)](https://codecov.io/gh/libraz/codehelion)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](https://www.rust-lang.org)

Rust / C / C++ のコードベースを対象に、重複ロジック（Type-1〜Type-3 クローン）と
コンパイル成果物の肥大化を検出し、その変化を追跡する、完全ローカル実行のコマンドライン
ツールです。ソースコードや解析結果を外部に送信せず、既定でネットワークアクセスを行いません。

> 開発初期段階です。ソースクローンエンジンは構築中で、現時点で CLI が提供するのは
> `doctor` 診断コマンドのみです。任意のコンパイラ／成果物バックエンドは後続リリースで追加します。

## インストール

```sh
cargo install codehelion   # `codehelion` コマンドが入ります
# もしくはチェックアウトから:
cargo install --path .
```

## 使い方

```sh
codehelion doctor   # 利用可能な解析コンポーネントを表示
codehelion --help
```

## 開発

ガードレールを一通り備えています。よく使う操作は `Makefile` にまとめてあります。

```sh
make format        # 自動修正: clippy --fix + cargo fmt
make format-check  # フォーマット検証 (CI と同一)
make lint          # clippy を警告エラー扱いで実行
make test          # テスト実行
make check         # format-check + lint + test + doc
make audit         # cargo-deny (脆弱性・禁止・ライセンス)
make coverage      # HTML カバレッジレポート (cargo-llvm-cov が必要)
make hooks         # pre-commit git フックを導入
```

### ガードレール

- **フォーマット** — 設定を固定した `rustfmt`。
- **Lint** — `clippy` の `pedantic` + `nursery` に加え、本体コードでの
  `unwrap` / `expect` / `panic` / `todo` を deny。`unsafe` は禁止。
- **テスト** — コードに隣接する単体テストと、ビルド済みバイナリを起動する
  E2E テスト。テストは対象コードと同時に書く。
- **サプライチェーン** — `cargo-deny` で脆弱性・ライセンス方針・依存重複を検査。
- **CI** — フォーマット / clippy / doc / テスト (Linux・macOS・Windows)、
  MSRV ビルド、カバレッジ。
- **pre-commit フック** — fmt / clippy / test に失敗するコミットを拒否。

## ディレクトリ構成

```text
src/
  main.rs      薄いバイナリのエントリポイント
  lib.rs       コマンドディスパッチ (単体テスト可能)
  cli.rs       clap のコマンド定義
  core/        エンジン層 (将来の codehelion-core crate の crate 内前身)
    doctor.rs  環境診断
tests/
  cli.rs       ビルド済みバイナリに対する E2E テスト
  fixtures/    単体・統合テスト用の小さな入力
corpus/        検出精度評価用 corpus (corpus/README.md を参照)
```

## ライセンス

[Apache License, Version 2.0](LICENSE) で提供します。
