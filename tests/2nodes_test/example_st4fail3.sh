#!/bin/sh
#	payment_hash不一致

ROUTECONF=pay_route.conf
AMOUNT=100000
PAY_BEGIN=4444
PAY_END=3333

PAYER=node_${PAY_BEGIN}
PAYER_PORT=$(( ${PAY_BEGIN} + 1 ))
PAYEE=node_${PAY_END}
PAYEE_PORT=$(( ${PAY_END} + 1 ))

nodeid() {
	cat conf/peer$1.conf | awk '(NR==3) { print $1 }' | cut -d '=' -f2
}

./routing -d $PAYER/dbucoin -s `nodeid $PAY_BEGIN` -r `nodeid $PAY_END` -a $AMOUNT
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
INVOICE=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff

./routing -d $PAYER/dbucoin -s `nodeid $PAY_BEGIN` -r `nodeid $PAY_END` -a $AMOUNT > $ROUTECONF

# 送金実施
./ucoincli -p $ROUTECONF,$INVOICE $PAYER_PORT
