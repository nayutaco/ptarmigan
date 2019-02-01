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

echo st4c start
./example_st4c.sh
sleep 5 # XXX: TODO
echo st4c end

echo st4d start
./example_st4d.sh
sleep 5 # XXX: TODO
echo st4d end

echo st4e start
./example_st4e.sh
sleep 5 # XXX: TODO
echo st4e end

echo st4f start
./example_st4f.sh
sleep 5 # XXX: TODO
echo st4f end

echo disconnect start
./example_st_quit.sh
sleep 5
echo disconnect end

echo clear skip route
for i in 3333 4444 5555 6666
do
    ./routing -d ./node_$i -c
done

echo reconnect start
./example_st_conn.sh
sleep 5
echo reconnect end

echo st4c start
./example_st4c.sh
sleep 5 # XXX: TODO
echo st4c end

echo st4d start
./example_st4d.sh
sleep 5 # XXX: TODO
echo st4d end

echo st4e start
./example_st4e.sh
sleep 5 # XXX: TODO
echo st4e end

echo st4f start
./example_st4f.sh
sleep 5 # XXX: TODO
echo st4f end

echo st5 start
./example_st5.sh
sleep 5 # XXX: TODO
echo st5 end

echo check proc count start
PROC_COUNT=`ps -C ptarmd | grep ptarmd | wc -l`
test $PROC_COUNT == 4
echo check proc count end

echo clean start
./clean.sh
echo clean end


END=`date +%s`
ELAPSED=`expr $END - $START` 
echo "$ELAPSED seconds"
