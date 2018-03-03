#!/bin/sh
FUNDIN_BTC=0.1
FUND_SAT=600000
PUSH_SAT=300000
CONFFILE=`pwd`/regtest.conf
DATADIR=`pwd`/regtest

cli() {
	bitcoin-cli -conf=$CONFFILE -datadir=$DATADIR $@
}

# BITCOIND_OPT=
# BITCOIND_VER=`cli getnetworkinfo | jq .version | sed -e 's/\([0-9][0-9]\).*/\1/'`
# if [ "$BITCOIND_VER" = "16" ]; then
# 	BITCOIND_OPT="-addresstype=legacy -deprecatedrpc=addwitnessaddress"
# fi

ADDR=`cli getnewaddress`
SEG=`cli addwitnessaddress $ADDR`
TXID=`cli sendtoaddress $SEG $FUNDIN_BTC`
echo txid=$TXID
CNT=`cli gettxout $TXID 0 | grep $SEG | wc -c`
if [ $CNT -gt 0 ]; then
	echo txindex=0
else
	echo txindex=1
fi
echo signaddr=$ADDR
echo funding_sat=$FUND_SAT
echo push_sat=$PUSH_SAT
