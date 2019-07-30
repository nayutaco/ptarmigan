#!/bin/sh
INSTALL_DIR=`pwd`/../../install
CONFFILE=`pwd`/regtest.conf
DATADIR=`pwd`/regtest

cli() {
	bitcoin-cli -conf=$CONFFILE -datadir=$DATADIR $@
}

mkdir regtest
if [ $? -ne 0 ]; then
	exit -1
fi

ln -s $INSTALL_DIR/ptarmcli ptarmcli
ln -s $INSTALL_DIR/ptarmd ptarmd
ln -s $INSTALL_DIR/showdb showdb
ln -s $INSTALL_DIR/routing routing
ln -s $INSTALL_DIR/default_conf.sh default_conf.sh
ln -s ../testfiles/regtest.conf regtest.conf
ln -s ../testfiles/generate.sh generate.sh
ln -s ../testfiles/getrawtx.sh getrawtx.sh
ln -s ../testfiles/sendrawtx.sh sendrawtx.sh

bitcoind -conf=$CONFFILE -datadir=$DATADIR -daemon
sleep 5
./generate.sh 432 > /dev/null
COUNT=`cli getblockcount`
if [ "${COUNT}" != "432" ]; then
	echo fail bitcoind
	exit 1
fi

sleep 3

# 1台のPCで複数ノードを立ち上げるので、ディレクトリをそれぞれ作る。
# 起動したディレクトリに関連ファイルを作成するためだ。
mkdir -p node_3333 node_4444 node_5555 node_6666
cp -ra $INSTALL_DIR/script node_3333/
cp -ra $INSTALL_DIR/script node_4444/
cp -ra $INSTALL_DIR/script node_5555/
cp -ra $INSTALL_DIR/script node_6666/
