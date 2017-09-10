#!/bin/sh

# このファイルから送金情報を作る。
# まだ自動的にルートを決めることができないので、手動で行う。
# 3行目が自ノードからnode_3333へ、4行目がnode_3333からnode_5555への送金を表している。
#   CSVの列は、node_id, short_channel_id, amount_msat, cltv、の順に並んでいる。
# 1行目は送金先からのpreimage_hash、2行目はルートの行数となっている。
#
#   +------------+             +-----------+
#   | node_4444  +------------>| node_3333 |
#   |            |  0.5mBTC    |           |
#   +------------+             |      |    |
#                              |------|----|
#   +------------+             |      v    |
#   | node_5555  |<------------| node_3333 |
#   |            |  0.5mBTC    |           |
#   +------------+             +-----------+

./routing node_4444/dbucoin node_4444/node.conf `./ucoind ./node_5555/node.conf id` 50000000
if [ $? -ne 0 ]; then
	echo no routing
	exit -1
fi

# pay設定ファイル出力
#		1: hash=(node_5555から取得したpayment_hash)
#		2: hop_num=3(以下の行数)
#		3: (node_4444 ID),(node_4444--node_3333間short_channel_id),0.5mBTC(msat),CLTV
#		4: (node_3333 ID),(node_3333--node_5555間short_channel_id),0.5mBTC(msat),CLTV
#		5: (node_5555 ID),0,0.5mBTC(msat),CLTV
#   ※実際にはFEEを含んだamountを使用すること
echo -n hash= > pay4444_3333_5555.conf
echo `./ucoincli -i 50000000 5556` | jq '.result.hash' | sed -e 's/\"//g' >> pay4444_3333_5555.conf
./routing node_4444/dbucoin node_4444/node.conf `./ucoind ./node_5555/node.conf id` 50000000 >> pay4444_3333_5555.conf

# 送金実施
./ucoincli -c conf/peer3333.conf -p pay4444_3333_5555.conf 4445

sleep 1

# 結果
./ucoincli -l 3334 > node_3333_after.cnl
./ucoincli -l 4445 > node_4444_after.cnl
./ucoincli -l 5556 > node_5555_after.cnl
