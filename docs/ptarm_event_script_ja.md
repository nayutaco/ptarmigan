# ptarmiganでイベント発生時に実行されるスクリプト

## 概要

* ptarmiganでは特定のイベントが発生した場合に、`ptarmd`を実行したディレクトリと同一の場所にある`script/`以下にあるスクリプトファイルを実行する。
* `install/`フォルダ内で`./new_nodedir.sh`を実行すると、`node/`ディレクトリを作成し、その中にサンプルの`srcipt/`をコピーする。

## スクリプトファイル

* `script/connected.sh`
  * peerと接続した

* `script/established.sh`
  * チャネルオープンした

* `script/closed.sh`
  * チャネルクローズした

* `script/payment.sh`
  * 送金開始

* `script/forward.sh`
  * 送金転送開始

* `script/fulfill.sh`
  * 着金受け入れ
  * 確定は`htlcchanged.sh`まで待ったほうが良い

* `script/fail.sh`
  * 着金キャンセル(送金ルートが使えなかった、など)

* `script/htlcchanged.sh`
  * HTLCの変更が確定した
    * `payment.sh`, `forward.sh`の後であれば、HTLCの追加が確定
    * `fufill.sh`, `fail.sh`のあとであれば、HTLCの反映が確定

* `script/error.sh`
  * peerからのエラー通知を受信した

## スクリプトファイルの使い方

* 各スクリプトの先頭に引数の意味が書かれているので、それを参照すること。
* 例: `script/htlcchanged.sh`

```bash
#   method: htlc_changed
#   $1: short_channel_id
#   $2: node_id
#   $3: our_msat
#   $4: htlc_num

short_channel_id: チャネルの16進数文字列(8byte)
node_id: 自node_idの16進数文字列(33byte)
our_msat: 現在の自分のamount量(単位:milli-satoshi)
htlc_num: HTLC数
```

```json
{"method":"htlc_changed","short_channel_id":"0001b10000020000","node_id":"024470061c7ae5c19633f0128a33ee7fd8e84e4b59b4c4dc0e055deb01d885376f","date":"2018-09-26T15:21:33.183975765","our_msat":300100000,"debug":"htlc_num=0"}
```

## 備考

* スクリプト内で`echo`しているのは単なる動作サンプルで、
* スクリプト内で`script/PTARMTEST.txt`を参照しているものがありますが、デバッグ用なので気にしないように。
