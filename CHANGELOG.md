CHANGELOG
====

# 2017/09/27

* 対面(no hop)でのc-lightningとの送受金


# 2017/09/25

* `ucoincli` の `-p` で `-c` を不要にする
    `-c` による事前の接続操作は必要

* BOLT#4 の onion version修正(0x01 --> 0x00)  
    [BOLT04: Correct the sphinx packet version in the implementation](https://github.com/lightningnetwork/lightning-rfc/commit/0310e40eda71e735f5d679d5fab2ded40956ef1a#diff-9198bb316a3387cc67fd543b03339b35)

* BOLT#8 の Key Rotation修正


# 2017/09/16

* 動作確認用スクリプトのbitcoin networkをregtestにする


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
