#!/bin/bash

# ノードの起動
#
# ここでは連続して起動させているが、動作を見る場合にはコンソールをそれぞれ開き、
# 各コンソールで起動させた方がログを見やすい。
create_kill_script() {
	# create killall script
	touch kill_ptarmd.sh
	echo "#!/bin/bash" > kill_ptarmd.sh
	for i in ${PID[@]}; do
		echo "kill -9 ${i}" >> kill_ptarmd.sh
	done
}


for i in 3333 4444
do
    cp ../testfiles/channel_$i.conf ./node_$i/channel.conf
    ./ptarmd -d ./node_$i -c ../regtest.conf -p $i --network=regtest > ./node_$i/ptarmd.log &
    PID+=($!)
done

while :
do
	sleep 1
	ls node_3333/ptarm_*.conf >/dev/null 2>&1
	if [ $? -ne 0 ]; then
		continue
	fi
	ls node_4444/ptarm_*.conf >/dev/null 2>&1
	if [ $? -ne 0 ]; then
		continue
	fi
	break
done

mkdir -p conf
rm -rf conf/*.conf
mv node_3333/ptarm_*.conf conf/peer3333.conf
mv node_4444/ptarm_*.conf conf/peer4444.conf

create_kill_script
