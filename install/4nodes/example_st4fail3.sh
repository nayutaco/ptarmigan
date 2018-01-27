#!/bin/sh
NETTYPE=regtest
ROUTECONF=pay_route.conf
AMOUNT=100000
PAY_BEGIN=4444
PAY_END=6666

PAYER=node_${PAY_BEGIN}
PAYER_PORT=$(( ${PAY_BEGIN} + 1 ))
PAYEE=node_${PAY_END}
PAYEE_PORT=$(( ${PAY_END} + 1 ))

./routing $NETTYPE $PAYER/dbucoin `./ucoind ./$PAYER/node.conf id` `./ucoind ./$PAYEE/node.conf id` $AMOUNT
if [ $? -ne 0 ]; then
	echo no routing
	exit -1
fi

INVOICE=`./ucoincli -i $AMOUNT $PAYEE_PORT`
if [ $? -ne 0 ]; then
	echo fail get invoice
	exit -1
fi

# preimage_hash無視
echo hash=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff > $ROUTECONF
./routing $NETTYPE $PAYER/dbucoin `./ucoind ./$PAYER/node.conf id` `./ucoind ./$PAYEE/node.conf id` $AMOUNT >> $ROUTECONF

# 送金実施
./ucoincli -p $ROUTECONF $PAYER_PORT
