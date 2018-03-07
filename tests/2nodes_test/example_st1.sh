#!/bin/sh
INSTALL_DIR=`pwd`/../../install
CONFFILE=`pwd`/regtest.conf
DATADIR=`pwd`/regtest
SLEEP_TM=3
BITCOIND_OPT=
BITCOIND_VER=`bitcoind --version | grep "Bitcoin Core Daemon" | sed -e 's/Bitcoin Core Daemon version v//' -e 's/\(0.1[5-6]\).*/\1/'`
if [ "$BITCOIND_VER" = "0.16" ]; then
	SLEEP_TM=6
	BITCOIND_OPT="-addresstype=legacy -deprecatedrpc=addwitnessaddress"
fi

cli() {
	bitcoin-cli -conf=$CONFFILE -datadir=$DATADIR $@
}

mkdir regtest
if [ $? -ne 0 ]; then
	exit -1
fi

ln -s $INSTALL_DIR/ucoincli ucoincli
ln -s $INSTALL_DIR/ucoind ucoind
ln -s $INSTALL_DIR/showdb showdb
ln -s $INSTALL_DIR/routing routing
ln -s ../testfiles/fund-test-in.sh fund-test-in.sh
ln -s ../testfiles/regtest.conf regtest.conf
ln -s ../testfiles/generate.sh generate.sh

bitcoind -conf=$CONFFILE -datadir=$DATADIR $BITCOIND_OPT -daemon
sleep $SLEEP_TM
cli generate 432

# 1台のPCで複数ノードを立ち上げるので、ディレクトリをそれぞれ作る。
# 起動したディレクトリに関連ファイルを作成するためだ。
mkdir -p node_3333 node_4444
ln -s $INSTALL_DIR/script node_3333/script
ln -s $INSTALL_DIR/script node_4444/script
