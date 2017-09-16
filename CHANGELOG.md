CHANGELOG
====

# 2017/09/16

* use `regtest`


# 2017/09/11

* `node_announcement` の `addresses` 対応
   * `node.conf` に `ipv4` 追加(オプション)

* chainhash を bitcoindから取得
    * `showdb`, `routing` に nettype(mainnet/testnet/regtest)オプション追加

* `showdb` に `p`(create peer config file)オプション追加  

* `routing` にグラフのみ作成する
    * `routing` の引数の数によってグラフのみ作成する機能追加


# 2017/09/10

* invoiceの保持をlnapp.cからucoind.cに移動
    * lnappはチャネルごとの情報を保存するが、payeeはどのチャネルで支払われるかを決めることができないため、ノードの情報として保持する


# 2017/09/07

* 内部的にJSON-RPCを使用する
    * 現時点でBOLTにはJSON-RPCへの取り決めがなく、また他を参考にもしていないため、lndやc-lightningとの互換性はない
    * TCP(HTTPではない)で、ポート番号は(ノードのポート番号+1)
    * `short_channel_id` は文字列扱い

* `node.conf` にbitcoindのRPC設定(rpcuser, rpcpasswd)が無い場合、 `~/.bitcoin/bitcoin.conf` を読む
