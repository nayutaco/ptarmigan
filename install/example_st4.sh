#!/bin/sh

# 各ノードが持つチャネル情報をファイル出力する。
# ファイル名は「ノードID.cnl」。
# ファイルには以下の順にコンマ区切りで出力されている。
#		相手ノードID,short_channel_id,自amount_msat,相手amount_msat
#
# チャネルごとに行が分かれているため、node_3333だけ2行ある。

./ucoincli -l 3333 > node_3333.cnl
./ucoincli -l 4444 > node_4444.cnl
./ucoincli -l 5555 > node_5555.cnl


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
#   |            |  0.4mBTC    |           |
#   +------------+             +-----------+

N3_NID=`./ucoind node_3333/node.conf id`
N4_NID=`./ucoind node_4444/node.conf id`
N5_NID=`./ucoind node_5555/node.conf id`

# (node_4444)3行目だけ取り出して、3列目(short_channel_id)を取り出す
N4_SCID=`cat node_4444.cnl | sed -n "3,3p" | cut -d, -f 3`

# (node_5555)3行目だけ取り出して、3列目(short_channel_id)を取り出す
N3_SCID=`cat node_5555.cnl | sed -n "3,3p" | cut -d, -f 3`

# pay設定ファイル出力
#		1: hash=(node_5555から取得したpayment_hash)
#		2: hop_num=3(以下の行数)
#		3: (node_4444 ID),(node_4444--node_3333間short_channel_id),0.5mBTC(msat),CLTV
#		4: (node_3333 ID),(node_3333--node_5555間short_channel_id),0.4mBTC(msat),CLTV
#		5: (node_5555 ID),0,0.4mBTC(msat),CLTV
# (最終行のmsatとCLTVは、その前と同じ値にしておく)。最終行のshort_channel_idは使っていない。
echo `./ucoincli -c conf/peer3333.conf -i 5555` > pay4444_3333_5555.conf
echo hop_num=3 >> pay4444_3333_5555.conf
echo $N4_NID,$N4_SCID,50000000,30 >> pay4444_3333_5555.conf
echo $N3_NID,$N3_SCID,40000000,20 >> pay4444_3333_5555.conf
echo $N5_NID,0,40000000,20 >> pay4444_3333_5555.conf

# 送金実施
./ucoincli -c conf/peer3333.conf -p pay4444_3333_5555.conf 4444

# 3秒以内には終わるはず
sleep 3

# 結果
./ucoincli -l 3333 > node_3333_after.cnl
./ucoincli -l 4444 > node_4444_after.cnl
./ucoincli -l 5555 > node_5555_after.cnl
