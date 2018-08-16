SRC = routing.c
OBJ = routing

include ../options.mak

CFLAGS = --std=c99 -D_GNU_SOURCE -I../include -I../ptarm/include -I../libs/install/include
LDFLAGS = -L../libs/install/lib -L../ptarm
LDFLAGS += -pthread -lptarm -llmdb -lbase58 -lmbedcrypto -lstdc++

ifeq ($(DISABLE_PRINTFUND),0)
CFLAGS += -DPTARM_USE_PRINTFUNC
endif

ifeq ($(ENABLE_DEVELOPER_MODE),1)
CFLAGS += -DDEVELOPER_MODE
endif

all: routing

routing: ../ptarm/libptarm.a $(SRC)
	gcc -W -Wall $(CFLAGS) -o $(OBJ) $(SRC) ../cmn/misc.c $(LDFLAGS)

clean:
	-rm -rf $(OBJ)
