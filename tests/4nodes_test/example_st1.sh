#!/bin/sh
INSTALL_DIR=`pwd`/../../install

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

bitcoind -conf=`pwd`/regtest.conf -datadir=`pwd`/regtest -daemon
sleep 3
bitcoin-cli -conf=`pwd`/regtest.conf -datadir=`pwd`/regtest generate 432

# 1台のPCで複数ノードを立ち上げるので、ディレクトリをそれぞれ作る。
# 起動したディレクトリに関連ファイルを作成するためだ。
mkdir -p node_3333 node_4444 node_5555 node_6666
ln -s $INSTALL_DIR/script node_3333/script
ln -s $INSTALL_DIR/script node_4444/script
ln -s $INSTALL_DIR/script node_5555/script
ln -s $INSTALL_DIR/script node_6666/script
