# CHANGELOG

## 2017/11/27

* unilateral closeでのpreimage監視追加(動作確認中)
* mutual closeでの`closing_tx`展開チェックを`getblock`式に変更
* DBバージョン更新

## 2017/11/23

* [`htlckey`](https://github.com/lightningnetwork/lightning-rfc/commit/4f91f0bb2a9c176dda019f9c0618c10f9fa0acfd) support
* DBバージョン更新

## 2017/11/20

* 2ノード間でのunilateral close
  * `payment_preimage` を持つトランザクションの監視機能は無い
* [`htlckey`](https://github.com/lightningnetwork/lightning-rfc/commit/4f91f0bb2a9c176dda019f9c0618c10f9fa0acfd) 未対応

## 2017/11/07

* 全channelのfunding_tx UTXO監視(`gettxout`)
* funding_txが使用されている場合、 `closing_signed` 受信後であればチャネル情報削除
* DBバージョン更新

## 2017/10/28

* issue #35: establish後、channel_announcement前でも、short_channel_idが存在するならば送金可能にする

## 2017/10/23

* issue #15: reestablish
* DBバージョン更新

## 2017/10/17

* issue #23: `funding_locked`後にDB保存する

## 2017/10/15

* issue#12: fail_htlcをcommitment_signed後にする
* イベントのタイミングでスクリプトを呼び出す
    * `./script/payment.sh` : 送金開始
    * `./script/forward.sh` : 送金を転送するとき
    * `./script/fulfaill.sh` : `update_fulfill_htlc` 送信時
    * `./script/fail.sh` : `update_fail_htlc` 送信時
    * `./script/htlcchanged.sh` : `revoke_and_ack` 後

## 2017/10/12

* issue#7: establish後に `minimum_depth` を待っている間に `announcement_signatures` を受信すると失敗する

## 2017/10/11

* チャネル再接続時、前回と `channel_update` が異なる場合には、作りなおして送信する。
* `channel_reestablish` 後の処理修正

## 2017/10/10

* announcement config file(`anno.conf`)およびestablish config file(`establish.conf`)追加
* `to_self_delay 修正`
* update libraries

## 2017/10/08

* c-lightningとの送受金テスト(2)
* コマンド引数変更

## 2017/10/02

* c-lightningとの中継送受金(1パターン)
  * ptarmigan --> c-lightning --> c-lightning
  * ptarmigan <-- c-lightning <-- c-lightning

## 2017/09/30

* c-lightningとの対面(no hop)送受金
  * ptarmigan --> c-lightning
  * ptarmigan <-- c-lightning

## 2017/09/25

* `ucoincli` の `-p` で `-c` を不要にする
  * `-c` による事前の接続操作は必要

* BOLT#4 の onion version修正(0x01 --> 0x00
    [BOLT04: Correct the sphinx packet version in the implementation](https://github.com/lightningnetwork/lightning-rfc/commit/0310e40eda71e735f5d679d5fab2ded40956ef1a#diff-9198bb316a3387cc67fd543b03339b35)

* BOLT#8 の Key Rotation修正

## 2017/09/16

* 動作確認用スクリプトのbitcoin networkをregtestにする

## 2017/09/11

* `node_announcement` の `addresses` 対応
  * `node.conf` に `ipv4` 追加(オプション)

* chainhash を bitcoindから取得
  * `showdb`, `routing` に nettype(mainnet/testnet/regtest)オプション追加

* `showdb` に `p`(create peer config file)オプション追加

* `routing` にグラフのみ作成する
  * `routing` の引数の数によってグラフのみ作成する機能追加

## 2017/09/10

* invoiceの保持をlnapp.cからucoind.cに移動
  * lnappはチャネルごとの情報を保存するが、payeeはどのチャネルで支払われるかを決めることができないため、ノードの情報として保持する

## 2017/09/07

* 内部的にJSON-RPCを使用する
  * 現時点でBOLTにはJSON-RPCへの取り決めがなく、また他を参考にもしていないため、lndやc-lightningとの互換性はない
  * TCP(HTTPではない)で、ポート番号は(ノードのポート番号+1)
  * `short_channel_id` は文字列扱い

* `node.conf` にbitcoindのRPC設定(rpcuser, rpcpasswd)が無い場合、 `~/.bitcoin/bitcoin.conf` を読む
