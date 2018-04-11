# [BOLT](https://github.com/lightningnetwork/lightning-rfc) compliant

## BOLT#1

* Setup Messages
  * `init` : `initial_routing_sync` = 1 のみ送信。受信したfeaturesは無視。
  * `error` : 受信結果をログに出す
  * `ping` and `pong`
    * 無送信状態が60秒継続すると、 `ping` を送信する
    * `pong`受信の際、前回の`ping`に対応するかチェックしない

## BOLT#2

* Channel Establishment
  * `feerate_per_kw`は `estimatesmartfee 6` の4分の1
    * 253未満の場合は、253にする([c-lightningに合わせる](https://github.com/ElementsProject/lightning/blob/957513666c494e35f71cb735eb82faed08f7b594/lightningd/chaintopology.c#L298))
  * `feerate_per_kw`の大きさチェックをしていない

* Channel Close
  * 相手が`closing_signed`を返した場合、同じ`fee_satoshis`を返す。

* Normal Operation
  * エラーメッセージに対応していない(箇所によってはabortする)。
  * `commitment_signed` がなかった場合の取消にまだ対応できておらず、受信メッセージをすぐに反映させている。

## BOLT#4

* Failure Messagesは実装中(固定値を返す)

## BOLT#5

* Closeの完了チェック(`closing_tx` の展開チェック)は `getblock` でTXIDが存在することを確認する
  * よって、1ブロック以上マイニングされないと完了しない

## BOLT#7

* Rebroadcastingは動作未確認
* Routingは `boost` の `dijkstra_shortest_paths()` を使用

## BOLT#11

* `description`は`ptarmigan`固定