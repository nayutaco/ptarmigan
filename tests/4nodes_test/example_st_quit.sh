#!/bin/sh

# ノードの停止
#

echo ------------------STOP-----------------------
for i in 3334 4445 5556 6667
do
    ./ptarmcli -q $i
done

while :
do
	PROC_COUNT=`ps -C ptarmd | grep ptarmd | wc -l`
	echo live procs: $PROC_COUNT
	if [ $PROC_COUNT -eq 0 ]; then
		break;
	fi
	sleep 1
done
echo ------------------STOP DONE-----------------------
