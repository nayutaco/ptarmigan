#!/bin/sh

# ノードの起動
#
# ここでは連続して起動させているが、動作を見る場合にはコンソールをそれぞれ開き、
# 各コンソールで起動させた方がログを見やすい。

export JDK_HOME=/usr/lib/jvm/java-8-openjdk-amd64
export JDK_CPU=amd64/server
export LD_LIBRARY_PATH=$JDK_HOME/jre/lib/$JDK_CPU
ls -l $LD_LIBRARY_PATH/libjvm.so

for i in 3333 4444
do
    rm -rf ./node_$i/dbptarm
    ./ptarmd -d ./node_$i -c ../regtest.conf -p $i &
done
