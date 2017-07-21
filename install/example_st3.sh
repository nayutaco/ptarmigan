#!/bin/sh

# チャネルを開く場合、segwitのP2WPKHアドレスから送金する必要があるのだが、
# bitcoindにsegwitのアドレスを探すのが大変なので、fund-in.sh の中で、
#       1. getnewaddressでP2PKHのアドレスを作る
#       2. addwitnessaddressで作ったアドレスのP2WPKHアドレスを作る
#       3. 2で作ったP2WPKHアドレスに送金する
# という手順を踏んでいる。
#
# fund.txt は単なるテキストファイルで、
#       * チャネルを開く際の amount [satoshi]
#       * そのうち、相手に渡す amount[satoshi]
# を記載する。
#
# 今のBOLT仕様(2017/07/06)では、チャネルを開こうとする方だけが amountを出すようになっていて、
# そのうちいくらかを相手に渡す(push_msat)ことになっている(本来はmili satoshiだが、ここではsatoshiにしている)。
# 相手に渡さなくてもよいが、その場合は他ノードから送金してもらうための amountがないため、
# 送金専用になってしまう。
# 自分の持ち分を渡して送金してもらっても嬉しくないが、そこをどう解決するのかはBOLTに書かれていない。
#
# チャネルを開く際には、example_st2.sh で送金した 9mBTCを使用する。
# funding_txに送金すれば完了するわけではなく、
# そこからブロックに取り込まれて、ある程度の confirmationを確認することになっている。
# confirmation数は、現在は実装埋め込みにしている(=1)。
# short_channel_id はブロックに取り込まれた情報を使って作成するため、0 にすることはできない。
#
# 今の実装では、チャネルを開くまでノードを終了させないようにしなくてはならない。
# confirmation数を確認するだけであれば、後から確認してもよいだろうが、まだそこまで実装できていない。
#
#
#   +------------+             +-----------+
#   | node_4444  +------------>| node_3333 |
#   |  4.9mBTC   |             |  5.0mBTC  |
#   +------------+             |           |
#                              |-----------|
#   +------------+             | node_3333 |
#   | node_5555  +------------>|  5.0mBTC  |
#   |  4.9mBTC   |             |           |
#   +------------+             +-----------+

# node_4444からnode_3333へチャネルを開く。
./ucoincli -c conf/peer3333.conf -f node_4444/fund4444_3333.conf 4444

# node_5555からnode_3333へチャネルを開く。
./ucoincli -c conf/peer3333.conf -f node_5555/fund5555_3333.conf 5555


# まだ動作が不安定なので、DBのバックアップを残しておく。
# うまく動作しなかったり、元に戻したいときは展開して上書きすればよい。
tar zcf node_3333/dbbak.tgz -C node_3333 dbucoin
tar zcf node_4444/dbbak.tgz -C node_4444 dbucoin
tar zcf node_5555/dbbak.tgz -C node_5555 dbucoin
