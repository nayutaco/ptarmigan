SRC = routing.c
OBJ = routing

include ../options.mak

CFLAGS = --std=c99 -D_GNU_SOURCE -I../utl -I../btc -I../ln -I../ptarmd -I../libs/install/include
LDFLAGS = -L../libs/install/lib -L../ln -L../btc -L../utl
LDFLAGS += -pthread -lln -lbtc -lutl -llmdb -lbase58 -lmbedcrypto -lstdc++

ifeq ($(DISABLE_PRINTFUND),0)
CFLAGS += -DPTARM_USE_PRINTFUNC
endif

ifeq ($(ENABLE_DEVELOPER_MODE),1)
CFLAGS += -DDEVELOPER_MODE
endif

all: routing

routing: ../ln/libln.a ../btc/libbtc.a ../utl/libutl.a $(SRC)
	gcc -W -Wall $(CFLAGS) -o $(OBJ) $(SRC) $(LDFLAGS)

clean:
	-rm -rf $(OBJ)
