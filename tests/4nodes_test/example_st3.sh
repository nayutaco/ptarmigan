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
# そのうちいくらかを相手に渡す(push_msat)ことになっている。
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
./ptarmcli -c conf/peer3333.conf 4445
./ptarmcli -c conf/peer3333.conf 5556
./ptarmcli -c conf/peer5555.conf 6667
sleep 3

# node_4444からnode_3333へチャネルを開く。
./ptarmcli -c conf/peer3333.conf -f 600000,300000000 4445

# node_5555からnode_3333へチャネルを開く。
./ptarmcli -c conf/peer3333.conf -f 600000,300000000 5556

# node_6666からnode_5555へチャネルを開く。
./ptarmcli -c conf/peer5555.conf -f 600000,300000000 6667

# 少し待つ
echo wait...
sleep 5

# mining
./generate.sh 6

while :
do
    CHN3=`./showdb -c -d node_3333 | jq '.[]|length'`
    CHN4=`./showdb -c -d node_4444 | jq '.[]|length'`
    CHN5=`./showdb -c -d node_5555 | jq '.[]|length'`
    CHN6=`./showdb -c -d node_6666 | jq '.[]|length'`
    NOD3=`./showdb -n -d node_3333 | jq '.[]|length'`
    NOD4=`./showdb -n -d node_4444 | jq '.[]|length'`
    NOD5=`./showdb -n -d node_5555 | jq '.[]|length'`
    NOD6=`./showdb -n -d node_6666 | jq '.[]|length'`
    echo CHAN3=$CHN3:$NOD3 CHAN4=$CHN4:$NOD4 CHAN5=$CHN5:$NOD5 CHAN6=$CHN6:$NOD6

    if [ "$CHN3" -eq 9 ] && [ "$CHN4" -eq 9 ] && [ "$CHN5" -eq 9 ] && [ "$CHN6" -eq 9 ] && [ "$NOD3" -eq 4 ] && [ "$NOD4" -eq 4 ] && [ "$NOD5" -eq 4 ] && [ "$NOD6" -eq 4 ]; then
        break
    fi
    sleep 3
done

#rm n3.txt n4.txt n5.txt n6.txt

echo @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
echo @ channel established
echo @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
