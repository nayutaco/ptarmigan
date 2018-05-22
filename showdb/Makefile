SRC = showdb.c
OBJ = showdb
CFLAGS = --std=c99 -D_GNU_SOURCE -I../include -I../ucoin/include -I../ucoin/libs/install/include
LDFLAGS = -L../libs/install/lib -L../ucoin/libs/install/lib -L../ucoin
LDFLAGS += -pthread -lucoin -llmdb -lsodium -lbase58 -lmbedcrypto -lzlog -lstdc++

all: showdb

showdb: ../ucoin/libucoin.a $(SRC)
	gcc -W -Wall $(CFLAGS) -o $(OBJ) $(SRC) ../cmn/misc.c $(LDFLAGS)

clean:
	-rm -rf $(OBJ) .Depend

.Depend:
ifneq ($(MAKECMDGOALS),clean)
	@$(CC) $(CFLAGS) -MM -MT $(SRC:%.c=%) $(SRC) > .Depend
endif

-include .Depend
