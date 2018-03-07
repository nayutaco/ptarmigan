# CHANGELOG

## 2018/03/07

* DB version : -17
  * most items were separated
* close処理中のDBをルート計算から除外する
* bitcoind v0.16暫定対応
  * nested in BIP16 P2SH(以前と同じレベル)
  * `estimatefee` --> `estimatesmartfee`

## 2018/03/03

* tag: 2018-03-03
  * DB version : - 16

## 2018/02/21

* `ucoincli -r`での送金リトライ機能
  * 送金途中で通れなかったチャネルをDB登録していく
  * 登録したチャネルは、今のところ削除できない

## 2018/02/18

* `feerate_per_kw`を設定可能にする
  * `fund.conf`に記載すると、その値を使用する
* change `fund-in.sh` to `pay_fundin.sh`
  * use `bc` command (`sudo apt install bc`)

```bash
pay_fundin.sh <pay to fund-in tx(satoshi)> <pay to our channel(satoshi)> <pay to their channel(satoshi)>
```

## 2018/02/17

* deprecate `node.conf`

## 2018/02/16

* `update_fee` receive

## 2018/02/14

* DB version update
  * 14 --> 15
* `shordb`, `routing`からchain種別の引数を削除

## 2018/02/12

* 相手からのclose時、remotekeyへの送金をbitcoindに戻す

## 2018/02/06

* DB version update
  * 13 --> 14
* `ping`/`pong`変更
  * `ping`は未送信状態が１分間経過すると送信する
    * 対応する`pong`を受信していない場合でも送信する(`lnd`が5分の未受信で接続するため)
  * `pong`受信はパケットの正常チェックのみ行い、前回の`ping`との対応はチェックしない
* 支払いのrouting計算の際、自チャネルの`channel_update`をチェックしない
  * BOLT#7の仕様に合わせる

## 2018/01/30

* DB version update
  * 12 --> 13
* ログ削減

## 2018/01/03

* Establish済みチャネルの開いてノードと未接続の場合、定期的に接続動作を行う
  * `node_announcement` でアドレス種別がIPv4の場合のみ
  * 間隔は30秒で、 closeチェック周期と同じ

## 2017/12/17

* BOLT11対応しようとして中断
  * mbedTLSに[署名から公開鍵を復元させるためのAPI](https://github.com/rustyrussell/lightning-payencode/blob/0bbbb3d00c2493a5eaaf2c13b11c4f4f7748a76c/lnaddr.py#L365)がないため
* payment_preimageの期限を1時間にする(preimage用DB変更)
  * BOLT11では、デフォルトで1時間と規定されているため

## 2017/12/08

* revoked transactionから直接取り戻す(動作確認中)
  * 以前は、revoked transaction closeした相手が送金するまで取り戻すことができなかった

## 2017/12/03

* revoked transaction closeでの監視(動作確認中)

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
