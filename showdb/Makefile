all: showdb

showdb: ../ucoin/libucoin.a showdb.c
	gcc -W -Wall --std=c99 -D_GNU_SOURCE -I../include -I../ucoin/include -I../ucoin/libs/install/include -o showdb showdb.c ../cmn/misc.c -L../libs/install/lib -L../ucoin/libs/install/lib -L../ucoin -llmdb -lucoin -lsodium -lbase58 -lmbedcrypto -pthread

clean:
	-rm -rf showdb
