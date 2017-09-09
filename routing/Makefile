all: routing

routing: routing.cpp
	g++ -Wall -ggdb -I../include -I../ucoin/include -I../libs/install/include -I../ucoin/libs/install/include -o routing routing.cpp ../cmn/conf.c ../cmn/misc.c -L../libs/install/lib -linih -L../ucoin/libs/install/lib -L../ucoin -llmdb -lucoin -lsodium -lbase58 -lmbedcrypto -pthread

clean:
	-rm -rf routing
