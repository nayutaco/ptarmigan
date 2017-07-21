#!/bin/sh

# ノードの起動
#
# ここでは連続して起動させているが、動作を見る場合にはコンソールをそれぞれ開き、
# 各コンソールで起動させた方がログを見やすい。
cd node_3333
../ucoind node.conf &
cd ../node_4444
../ucoind node.conf &
cd ../node_5555
../ucoind node.conf &
cd ..


# 0.01BTC(10mBTC)をP2WPKHアドレスに送金している。
# fund.txt は、そのうち 9.9mBTC でチャネルを開き、5.0mBTCを相手に渡している。
# なぜ 10mBTCで開かないかというと、P2WPKHアドレスからさらに funding_txに送金するため、
# その分の FEEが必要になるからである(1mBTCもいらないとは思うが)。
./fund-in.sh 0.01 fund.txt > node_4444/fund4444_3333.conf
./fund-in.sh 0.01 fund.txt > node_5555/fund5555_3333.conf
