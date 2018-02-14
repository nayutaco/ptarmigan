#!/bin/bash

if [ -z "$1" ] || [ -z "$2" ] || [ -z "$3" ]; then
	echo invalid parameter [$1] [$2] [$3]
	echo [payer] [payee] [amount]
	exit 128
fi

PAY_BEGIN=$1
PAY_END=$2
AMOUNT=$3

PAYER=node_${PAY_BEGIN}
PAYER_PORT=$(( ${PAY_BEGIN} + 1 ))
PAYEE=node_${PAY_END}
PAYEE_PORT=$(( ${PAY_END} + 1 ))


pay() {
	echo "payment ${PAYER} --> ${PAYEE}"

	INVOICE=`./ucoincli -i $AMOUNT $PAYEE_PORT`
	if [ $? -ne 0 ]; then
		echo fail get invoice
		exit 2
	fi

	ROUTEPAY=`echo $INVOICE | jq -r '.result.bolt11'`

	# 送金実施
	./ucoincli -r $ROUTEPAY $PAYER_PORT
	if [ $? -ne 0 ]; then
		echo fail payment
		exit 3
	fi
}

pay
