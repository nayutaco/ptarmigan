#!/bin/sh
set -eu

if [ $# -ne 3 ]; then
	echo "create fund-in information file."
	echo "  - create P2WPKH address"
	echo "  - pay from bitcoind to the address"
	echo
	echo "  usage:"
	echo "    pay_fundin.sh <pay to P2WPKH(satoshi)> <pay to our channel(satoshi)> <pay to their channel(satoshi)>"
	return 1
fi

FUNDIN_CONF=fund_`date +%Y%m%d%H%M%S`.conf
FUNDIN_BTC=`echo "scale=10; $1/100000000" | bc`
FUNDIN_BTC=`printf "%.8f" $FUNDIN_BTC`
FUND_SAT=$2
PUSH_SAT=$3

if [ $1 -le $FUND_SAT ]; then
	echo "ERROR: arg1(funding satoshis) <= arg2(channel satoshis)"
	echo "  note: [funding satoshis] >= [channel satoshis] + [funding_tx fee]"
	return 2
fi
if [ $FUND_SAT -le $PUSH_SAT ]; then
	echo "ERROR: arg2(channel satoshis) <= arg3(push satoshis)"
	return 3
fi

CONFFILE=~/.bitcoin/bitcoin.conf
DATADIR=~/.bitcoin

cli() {
	bitcoin-cli -conf=$CONFFILE -datadir=$DATADIR $@
}

OPT_GENERATE=
BITCOIND_VER=`cli getnetworkinfo | jq .version | sed -e 's/\([0-9][0-9]\).*/\1/'`
if [ "$BITCOIND_VER" = "16" ]; then
	OPT_GENERATE="p2sh-segwit"
fi

ADDR=
SEG=
if [ "$BITCOIND_VER" = "16" ]; then
	ADDR=`cli getnewaddress "" p2sh-segwit`
	SEG=$ADDR
else
	ADDR=`cli getnewaddress`
	SEG=`cli addwitnessaddress $ADDR`
fi
TXID=`cli sendtoaddress $SEG $FUNDIN_BTC`
echo txid=$TXID > $FUNDIN_CONF
CNT=`cli gettxout $TXID 0 | grep $SEG | wc -c`
if [ $CNT -gt 0 ]; then
	echo txindex=0 >> $FUNDIN_CONF
else
	echo txindex=1 >> $FUNDIN_CONF
fi
echo signaddr=$ADDR >> $FUNDIN_CONF
echo funding_sat=$FUND_SAT >> $FUNDIN_CONF
echo push_sat=$PUSH_SAT >> $FUNDIN_CONF

echo "create: $FUNDIN_CONF"
