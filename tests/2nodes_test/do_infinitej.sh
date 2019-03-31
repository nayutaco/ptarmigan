#!/bin/bash -ue

rm -f count.txt
count=0
while :
do
  count=$((count+1))
  echo ${count} > count.txt
  ./all_testj.sh
done
