all: showdb

showdb: showdb.c
	gcc -Wall -I../include -I../ucoin/include -I../ucoin/libs/install/include -o showdb showdb.c -L../libs/install/lib -L../ucoin/libs/install/lib -L../ucoin -llmdb -lucoin -lsodium -lbase58 -lmbedcrypto -pthread

clean:
	-rf -rf showdb
