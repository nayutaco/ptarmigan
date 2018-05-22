SRC = showdb.c
OBJ = showdb

include ../common.mak

CFLAGS = --std=c99 -D_GNU_SOURCE -I../include -I../ucoin/include -I../ucoin/libs/install/include
LDFLAGS = -L../libs/install/lib -L../ucoin/libs/install/lib -L../ucoin
LDFLAGS += -pthread -lucoin -llmdb -lsodium -lbase58 -lmbedcrypto -lzlog -lstdc++

ifeq ($(DISABLE_PRINTFUND),0)
CFLAGS += -DUCOIN_USE_PRINTFUNC
endif

all: showdb

showdb: ../ucoin/libucoin.a $(SRC)
	gcc -W -Wall $(CFLAGS) -o $(OBJ) $(SRC) ../cmn/misc.c $(LDFLAGS)

clean:
	-rm -rf $(OBJ)
