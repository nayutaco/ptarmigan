CHANGELOG
====

# 2017/09/07

* 内部的にJSON-RPCを使用する
    * 現時点でBOLTにはJSON-RPCへの取り決めがなく、また他を参考にもしていないため、lndやc-lightningとの互換性はない
    * TCP(HTTPではない)で、ポート番号は(ノードのポート番号+1)
    * `short_channel_id` は文字列扱い

* `node.conf` にbitcoindのRPC設定(rpcuser, rpcpasswd)が無い場合、 `~/.bitcoin/bitcoin.conf` を読む
