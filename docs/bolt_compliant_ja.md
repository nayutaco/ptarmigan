# [BOLT](https://github.com/lightningnetwork/lightning-rfc) compliant

## BOLT#1

* Setup Messages
  * `init` : `channel.conf`の設定に従ってlocalfeaturesを送信する
  * `error` : 受信結果をログに出す
  * `ping` and `pong`
    * 無送信状態が60秒継続すると、 `ping` を送信する
    * `pong`受信の際、前回の`ping`に対応するかチェックしない(c-lightningのDEVELOPER対策)

## BOLT#2

* Channel Establishment
  * `feerate_per_kw`は `estimatesmartfee 6` の4分の1
    * 253未満の場合は、253にする([c-lightningに合わせる](https://github.com/ElementsProject/lightning/blob/957513666c494e35f71cb735eb82faed08f7b594/lightningd/chaintopology.c#L298))
  * `feerate_per_kw`の大きさチェックをしていない

* Channel Close
  * 相手が`closing_signed`を返した場合、同じ`fee_satoshis`を返す。

## BOLT#4

* `expiry_too_soon`
  * `cltv_expiry`が現在のblock heightで期待する値より2以上小さい
  * `cltv_expiry`が7未満
* `expiry_too_far`
  * `cltv_expiry`が約15日(144*15block)以上

## BOLT#5

* Closeの完了チェック(`closing_tx` の展開チェック)は `getblock` でTXIDが存在することを確認する
  * よって、1ブロック以上マイニングされないと完了しない

## BOLT#7

* Routingは `boost` の `dijkstra_shortest_paths()` を使用

## BOLT#11

* `description`は`ptarmigan`固定