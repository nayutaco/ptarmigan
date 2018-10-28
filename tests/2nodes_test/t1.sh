#!/bin/sh
./ptarmcli --debug 1 3334
./example_st4e.sh
sleep 5
./ptarmcli -c conf/peer3333.conf -xforce 4445

