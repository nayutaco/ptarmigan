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


# このファイルから送金情報を作る。
# CSVの列は、node_id, short_channel_id, amount_msat, cltv、の順に並んでいる。
# 1行目は送金先からのpreimage_hash、2行目はルートの行数となっている。
#
#  +-----------+             +-----------+
#  | node_4444 +------------>| node_3333 |
#  |           |             |           |
#  +-----------+             |      |    |
#                            +------|----+
#  +-----------+             |      v    |
#  | node_5555 |<------------+ node_3333 |
#  |           |             |           |
#  |   |       |             +-----------+
#  +---|-------+
#  |   v       |             +-----------+
#  | node_5555 |             | node_6666 |
#  |           +------------>|           |
#  +-----------+             +-----------+

./routing $NETTYPE $PAYER/dbucoin $PAYER/node.conf `./ucoind ./$PAYEE/node.conf id` $AMOUNT
if [ $? -ne 0 ]; then
	echo no routing
	exit -1
fi

# pay設定ファイル出力
#		1: hash=(node_5555から取得したpayment_hash)
#		2: hop_num=3(以下の行数)
#		3: (node_4444 ID),(node_4444--node_3333間short_channel_id),0.5mBTC(msat),CLTV
#		4: (node_3333 ID),(node_3333--node_5555間short_channel_id),0.5mBTC(msat),CLTV
#		5: (node_5555 ID),(node_5555--node_6666間short_channel_id),0.5mBTC(msat),CLTV
#		6: (node_6666 ID),0,0.5mBTC(msat),CLTV
#   ※実際にはFEEを含んだamountを使用すること
INVOICE=`./ucoincli -i $AMOUNT $PAYEE_PORT`
if [ $? -ne 0 ]; then
	echo fail get invoice
	exit -1
fi

echo -n hash= > $ROUTECONF
echo $INVOICE | jq '.result.hash' | sed -e 's/\"//g' >> $ROUTECONF
./routing $NETTYPE $PAYER/dbucoin $PAYER/node.conf `./ucoind ./$PAYEE/node.conf id` $AMOUNT >> $ROUTECONF

# 送金実施
./ucoincli -p $ROUTECONF $PAYER_PORT
