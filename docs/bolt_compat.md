# [BOLT](https://github.com/lightningnetwork/lightning-rfc) compliant

## BOLT#1

* Setup Messages
  * `init` : `initial_routing_sync` = 0 のみ送信。受信したfeaturesは無視。
  * `error` : 受信結果をログに出す
  * `ping` and `pong` : 無通信状態が60秒継続すると、 `ping` を送信する

## BOLT#2

* Channel Close
  * FEEは相手と同じ値を即座に返している(実際は、FEEの認識が合うまで通信し合うようになっている)。

* Normal Operation
  * エラーメッセージに対応していない(abortする)。
  * `commitment_signed` がなかった場合の取消にまだ対応できておらず、受信メッセージをすぐに反映させている。

* Message Retransmission
  * `funding_locked` 交換しないと再接続できない

## BOLT#3

* Commitment Transaction
  * HTLCは1つまでしか動作確認していない
  * CLTV, CSVのタイムアウトは監視していない

## BOLT#4

* Failure Messagesは実装中(固定値を返す)

## BOLT#5

* Mutual Close以外は確認していない

## BOLT#7

* Initial Syncは行っていない
* Rebroadcastingは動作未確認
* Routingは `boost` の `dijkstra_shortest_paths()` を使用
