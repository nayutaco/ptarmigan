SRC = showdb.c
OBJ = showdb

include ../options.mak

CFLAGS = --std=c99 -D_GNU_SOURCE -I../util -I../btc -I../ln -I../ptarmd -I../libs/install/include
LDFLAGS = -L../libs/install/lib -L../ln -L../btc -L../util
LDFLAGS += -pthread -lln -lbtc -lutil -llmdb -lbase58 -lmbedcrypto -lstdc++

ifeq ($(DISABLE_PRINTFUND),0)
CFLAGS += -DPTARM_USE_PRINTFUNC
endif

ifeq ($(ENABLE_DEVELOPER_MODE),1)
CFLAGS += -DDEVELOPER_MODE
endif

all: showdb

showdb: ../ln/libln.a ../btc/libbtc.a ../util/libutil.a $(SRC)
	gcc -W -Wall $(CFLAGS) -o $(OBJ) $(SRC) $(LDFLAGS)

clean:
	-rm -rf $(OBJ)
