SRC = showdb.c
OBJ = showdb

include ../options.mak

CC              := "$(GNU_PREFIX)gcc"

CFLAGS  += --std=c99 -I../utl -I../btc -I../ln -I../ptarmd -I../libs/install/include -O3
LDFLAGS += -L../libs/install/lib -L../ln -L../btc -L../utl
LDFLAGS += -pthread -lln -lbtc -lutl -llmdb -lbase58 -lmbedcrypto -lz -lstdc++
ifeq ($(USE_OPENSSL),1)
	LDFLAGS += -lssl -lcrypto -ldl
endif

all: showdb

showdb: ../ln/libln.a ../btc/libbtc.a ../utl/libutl.a $(SRC)
	$(CC) -W -Wall -Werror $(CFLAGS) -o $(OBJ) $(SRC) $(LDFLAGS)

clean:
	-rm -rf $(OBJ)
