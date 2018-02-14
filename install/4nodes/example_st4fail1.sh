#!/bin/sh
ROUTECONF=pay_route.conf
AMOUNT=100000
PAY_BEGIN=4444
PAY_END=6666

PAYER=node_${PAY_BEGIN}
PAYER_PORT=$(( ${PAY_BEGIN} + 1 ))
PAYEE=node_${PAY_END}
PAYEE_PORT=$(( ${PAY_END} + 1 ))

echo 途中のノードがないため、中継ノードで失敗する


./routing $PAYER/dbucoin `./ucoind ./$PAYER/node.conf id` `./ucoind ./$PAYEE/node.conf id` $AMOUNT
if [ $? -ne 0 ]; then
	echo no routing
	exit -1
fi

echo -n hash= > $ROUTECONF
echo `./ucoincli -i $AMOUNT $PAYEE_PORT` | jq -r '.result.hash' >> $ROUTECONF
./routing $PAYER/dbucoin `./ucoind ./$PAYER/node.conf id` `./ucoind ./$PAYEE/node.conf id` $AMOUNT >> $ROUTECONF

# 強制的に中間のノードを終了させる
./ucoincli -q 5556
sleep 3

# 送金実施
./ucoincli -p $ROUTECONF $PAYER_PORT
