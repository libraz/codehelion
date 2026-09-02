# calibration

> **1.0 前の面です。** 文書化もテストもされていますが、約束に値するだけの実利用を経ていないため、リリース間で変わり得ます。

calibration が答えるのは「見積もりはどれだけ当たっていたか」です。ソーススキャンはあるクローングループの費用を見積もれますが、それを取り除いて成果物から実際に何が減ったかを言えるのは実ビルド 2 つだけです。calibration はその 2 つを並べて記録します。

## どの数値が何か

savings は別々の量として報告し、ひとつの数値にまとめることはありません。

| 数値 | 意味 |
|---|---|
| observed | 成果物が現に含んでいる、実測した量 |
| duplicated | そのうち、他の何かの繰り返しである量 |
| retained | 重複が消えたときに到達可能なまま残る量 |
| upper bound | 最も有利な仮定のもとで取り除ける最大量 |
| estimated | 1 つのクローングループについてモデルが予測する量 |
| verified | 実ビルド 2 つが実際に示した差 |

`upper_bound_savings` は削減の保証値ではなく、そのように表示することもありません。対象そのものの計測から来るのは verified だけで、その verified も次の条件のもとでしか言葉どおりの意味を持ちません。

## 計測を記録する

計測を記録するのは `artifact compare` で、`--source-run` と `--clone-group` を `--before-build-variant` / `--after-build-variant` と併せて渡したときです。そのグループについて保存済みの見積もりと、2 つの成果物が実際に示したサイズ差を並べます。ここで必要になる見積もりは、先に `--source-run` と `--build-variant` を付けて実行した `artifact analyze` が残します。

```sh
codehelion artifact analyze before/app.wasm --source-run 6 --build-variant build-variant.json
# ... 重複を取り除いてビルドし直す ...
codehelion artifact compare before/app.wasm after/app.wasm \
  --source-run 6 --clone-group b92c1297 \
  --before-build-variant build-variant.json \
  --after-build-variant build-variant.json
```

## verified の数値が意味すること、しないこと

キャリブレーション付きの比較から出てくる `verified_savings_bytes` は、2 つの成果物のあいだで観測されたサイズ差をまるごと、`--clone-group` で名指しした 1 つのクローングループに帰属させた値です。この比較が確かめるのは、両方の成果物が同じフォーマットであることと、宣言された build variant が同じであることだけで、それ以上は確かめません。依存の更新やツールチェーンの変更を一緒に拾ったビルド対では、その差も含めてリファクタリングの計測値として報告されます。この数値が言葉どおりの意味を持つのは、2 つの成果物がそれ以外の点で何も違わないときだけです。

## 記録済みの計測を集計する

```sh
codehelion artifact calibration                 # 記録済みの計測を集計
codehelion artifact calibration --source-run 1  # 特定のソーススキャンを集計
```

`artifact calibration` は計測を取るコマンドではなく読むコマンドなので、計測が 1 件も無ければ集計する対象もありません。

## 2 つの集計を比べる

```sh
codehelion artifact calibration --format json --output calibration.json
# ... 時間をおいて ...
codehelion artifact calibration --baseline calibration.json
```

`--baseline <file>` には、以前書き出した集計レポートを渡します。全体と stratum ごとに、各誤差統計が現在値との間でどれだけ動いたかを並べて表示します。行うのは比較と報告だけで、閾値は課さず、差が出ても失敗にはしません。calibration レポートのスキーマが異なるものは、比較せずエラーとして拒否します。
