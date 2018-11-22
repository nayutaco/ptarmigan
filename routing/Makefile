SRC = routing.c
OBJ = routing

include ../options.mak

CC              := "$(GNU_PREFIX)gcc"

CFLAGS  += --std=c99 -I../utl -I../btc -I../ln -I../ptarmd -I../libs/install/include
LDFLAGS += -L../libs/install/lib -L../ln -L../btc -L../utl
LDFLAGS += -pthread -lln -lbtc -lutl -llmdb -lbase58 -lmbedcrypto -lstdc++

all: routing

routing: ../ln/libln.a ../btc/libbtc.a ../utl/libutl.a $(SRC)
	$(CC) -W -Wall $(CFLAGS) -o $(OBJ) $(SRC) $(LDFLAGS)

clean:
	-rm -rf $(OBJ)
