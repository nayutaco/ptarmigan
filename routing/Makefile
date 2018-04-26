OBJ = routing
CFLAGS = -I../include -I../ucoin/include -I../libs/install/include -I../ucoin/libs/install/include
LDFLAGS = -L../libs/install/lib -L../ucoin/libs/install/lib -L../ucoin
LDFLAGS += -linih -lucoin -lsodium -llmdb -lbase58 -lmbedcrypto -pthread -lstdc++

all: routing

routing:
	gcc -o $(OBJ)  -W -Wall -ggdb $(CFLAGS) ../cmn/misc.c routing_main.c $(LDFLAGS)

clean:
	-rm -rf $(OBJ) *.o .Depend
