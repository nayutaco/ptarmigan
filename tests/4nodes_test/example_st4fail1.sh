#!/bin/sh
#	送金中にノード不在
#	4444 --> 3333 --> (x 5555) --> 6666

ROUTECONF=pay_route.conf
AMOUNT=100000
PAY_BEGIN=4444
PAY_END=6666

PAYER=node_${PAY_BEGIN}
PAYER_PORT=$(( ${PAY_BEGIN} + 1 ))
PAYEE=node_${PAY_END}
PAYEE_PORT=$(( ${PAY_END} + 1 ))

echo 途中のノードがないため、中継ノードで失敗する


nodeid() {
	cat conf/peer$1.conf | awk '(NR==3) { print $1 }' | cut -d '=' -f2
}

./routing -d $PAYER -s `nodeid $PAY_BEGIN` -r `nodeid $PAY_END` -a $AMOUNT
if [ $? -ne 0 ]; then
	echo no routing
	exit -1
fi

echo -n hash= > $ROUTECONF
echo `./ptarmcli -i $AMOUNT $PAYEE_PORT` | jq -r '.result.hash' >> $ROUTECONF
./routing -d $PAYER -s `nodeid $PAY_BEGIN` -r `nodeid $PAY_END` -a $AMOUNT >> $ROUTECONF

# 強制的に中間のノードを終了させる
./ptarmcli -q 5556
sleep 3

# 送金実施
./ptarmcli -p $ROUTECONF $PAYER_PORT
