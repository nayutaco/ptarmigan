#!/bin/bash -ue

START=`date +%s`

echo clean start
./clean.sh >/dev/null 2>&1 | :
echo clean end

echo st1 start
./example_st1.sh
echo st1 end

echo st2 start
./example_st2.sh
sleep 5 # wait conf file
echo st2 end

echo st3 start
./example_st3.sh
sleep 5 # XXX: TODO
echo st3 end

echo reconnect start
./example_st_conn.sh
sleep 5
echo reconnect end

echo st4fail1b start
./example_st4fail1b.sh
sleep 5 # XXX: TODO
echo st4d end

#echo check proc count start
#PROC_COUNT=`ps -C ptarmd | grep ptarmd | wc -l`
#test $PROC_COUNT == 4
#echo check proc count end

echo check log
BAD_LINE_COUNT=`../../tools/log_filter.sh | wc -l`
if [ $BAD_LINE_COUNT -ne 0 ];
then
    ../../tools/log_filter.sh
    exit 1
fi
echo check log end

echo clean start
./clean.sh
echo clean end

END=`date +%s`
ELAPSED=`expr $END - $START` 
echo "$ELAPSED seconds"
