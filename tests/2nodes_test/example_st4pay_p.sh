#!/bin/bash

if [ -z "$1" ] || [ -z "$2" ] || [ -z "$3" ]; then
	echo invalid parameter [$1] [$2] [$3] [$4]
	echo [payer] [payee] [amount] {loop}
	exit 128
fi

PAY_BEGIN=$1
PAY_END=$2
AMOUNT=$3

ROUTECONF=pay_route_${PAY_BEGIN}_${PAY_END}.conf
PAYER=node_${PAY_BEGIN}
PAYER_PORT=$(( ${PAY_BEGIN} + 1 ))
PAYEE=node_${PAY_END}
PAYEE_PORT=$(( ${PAY_END} + 1 ))

nodeid() {
	cat conf/peer$1.conf | awk '(NR==3) { print $1 }' | cut -d '=' -f2
}

pay() {
	payer_id=`nodeid $PAY_BEGIN`
	payee_id=`nodeid $PAY_END`
	echo "payment ${PAYER}:${payer_id} --> ${PAYEE}:${payee_id}"

	./routing -d $PAYER/dbucoin -s $payer_id -r $payee_id -a $AMOUNT
	if [ $? -ne 0 ]; then
		echo no routing
		exit 1
	fi

	INVOICE=`./ucoincli -i $AMOUNT $PAYEE_PORT`
	if [ $? -ne 0 ]; then
		echo fail get invoice
		exit 2
	fi

	HASH=`echo $INVOICE | jq -r '.result.hash'`
	./routing -d $PAYER/dbucoin -s $payer_id -r $payee_id -a $AMOUNT > $ROUTECONF

	# 送金実施
	./ucoincli -p $ROUTECONF,$HASH $PAYER_PORT
	if [ $? -ne 0 ]; then
		echo fail payment
		exit 3
	fi
}

pay
while [ -n "$4" ]
do
	utime=1.$(( 100 + $RANDOM % 400))
	# sudo apt install sleepenh
	sleepenh $utime
	pay
done
