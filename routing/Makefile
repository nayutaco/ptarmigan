SRC = ln_routing.cpp
OBJ = routing
CFLAGS = -I../include -I../ucoin/include -I../libs/install/include -I../ucoin/libs/install/include
LDFLAGS = -L../libs/install/lib -L../ucoin/libs/install/lib -L../ucoin
LDFLAGS += -linih -llmdb -lucoin -lsodium -lbase58 -lmbedcrypto -pthread

all: lnrouting routing

routing: $(SRC)
	gcc -c -W -Wall -ggdb $(CFLAGS) ../cmn/misc.c
	gcc -c -W -Wall -ggdb $(CFLAGS) routing_main.c
	g++ -o $(OBJ)  -W -Wall -ggdb $(CFLAGS) ln_routing.o misc.o routing_main.o $(LDFLAGS) -lgcc

lnrouting:
	g++ -c -W -Wall -ggdb $(CFLAGS) $(SRC)

clean:
	-rm -rf $(OBJ) *.o .Depend

.Depend:
ifneq ($(MAKECMDGOALS),clean)
	@$(CC) $(CFLAGS) -MM -MT $(SRC:%.cpp=%) $(SRC) > .Depend
endif

-include .Depend
