#!/bin/sh
# 0.01BTC(10mBTC)をP2WPKHアドレスに送金している。
# fund.txt は、そのうち 9.0mBTC でチャネルを開き、5.0mBTCを相手に渡している。
# なぜ 10mBTCで開かないかというと、P2WPKHアドレスからさらに funding_txに送金するため、
# その分の FEEが必要になるからである(1mBTCもいらないとは思うが)。

# チャネルを開く場合、segwitのP2WPKHアドレスから送金する必要があるのだが、
# bitcoindにsegwitのアドレスを探すのが大変なので、fund-test-in.sh の中で、
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
# そのうちいくらかを相手に渡す(push_msat)ことになっている(本来はmilli satoshiだが、ここではsatoshiにしている)。
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
#  +-----------+             +-----------+
#  | node_4444 +-------------+ node_3333 |
#  |    FUNDER |             |           |
#  +-----------+             |    fundee |
#                            +-----------+
#  +-----------+             | node_3333 |
#  | node_5555 +-------------+           |
#  |           |             |    fundee |
#  |    FUNDER |             +-----------+
#  +-----------+
#  | node_5555 |             +-----------+
#  |           |             | node_6666 |
#  |    fundee +-------------+    FUNDER |
#  +-----------+             +-----------+

mkdir -p conf
rm -rf conf/*.conf
mv node_3333/ptarm_*.conf conf/peer3333.conf
mv node_4444/ptarm_*.conf conf/peer4444.conf
mv node_5555/ptarm_*.conf conf/peer5555.conf
mv node_6666/ptarm_*.conf conf/peer6666.conf

# connect
./ucoincli -c conf/peer3333.conf 4445
sleep 1
./ucoincli -c conf/peer3333.conf 5556
sleep 1
./ucoincli -c conf/peer5555.conf 6667
sleep 1

# node_4444からnode_3333へチャネルを開く。
./fund-test-in.sh > node_4444/fund4444_3333.conf
sleep 1
./ucoincli -c conf/peer3333.conf -f node_4444/fund4444_3333.conf 4445

sleep 3

# node_5555からnode_3333へチャネルを開く。
./fund-test-in.sh > node_5555/fund5555_3333.conf
sleep 1
./ucoincli -c conf/peer3333.conf -f node_5555/fund5555_3333.conf 5556

sleep 3

# node_6666からnode_5555へチャネルを開く。
./fund-test-in.sh > node_6666/fund6666_5555.conf
sleep 1
./ucoincli -c conf/peer5555.conf -f node_6666/fund6666_5555.conf 6667

# 少し待つ
echo wait...
sleep 20

# mining
bitcoin-cli -conf=`pwd`/regtest.conf -datadir=`pwd` generate 6

# 少し待つ
echo wait............
while :
do
    ./showdb c node_3333/dbucoin/ | jq '.' > n3.txt
    ./showdb c node_4444/dbucoin/ | jq '.' > n4.txt
    ./showdb c node_5555/dbucoin/ | jq '.' > n5.txt
    ./showdb c node_6666/dbucoin/ | jq '.' > n6.txt
    cmp n3.txt n4.txt
    RES1=$?
    cmp n3.txt n5.txt
    RES2=$?
    cmp n3.txt n6.txt
    RES3=$?

    LEN3=`cat n3.txt | jq length`
    LEN4=`cat n4.txt | jq length`
    LEN5=`cat n5.txt | jq length`
    LEN6=`cat n6.txt | jq length`

    if [ -n "$LEN3" ] && [ -n "$LEN4" ] && [ -n "$LEN5" ] && [ -n "$LEN6" ] && [ "$LEN3" -ne 0 ] && [ "$LEN4" -ne 0 ] && [ "$LEN5" -ne 0 ] && [ "$LEN6" -ne 0 ] && [ "$RES1" -eq 0 ] && [ "$RES2" -eq 0 ] && [ "$RES3" -eq 0 ]; then
        break
    fi
    sleep 3
done

rm n3.txt n4.txt n5.txt n6.txt

echo @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
echo @ channel established
echo @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
