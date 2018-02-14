SRC = routing.cpp
OBJ = routing
CFLAGS = -I../include -I../ucoin/include -I../libs/install/include -I../ucoin/libs/install/include
LDFLAGS = -L../libs/install/lib -L../ucoin/libs/install/lib -L../ucoin
LDFLAGS += -linih -llmdb -lucoin -lsodium -lbase58 -lmbedcrypto -pthread

all: .Depend routing

routing: $(SRC)
	g++ -W -Wall -ggdb $(CFLAGS) -o $(OBJ) $(SRC) ../cmn/conf.c ../cmn/misc.c $(LDFLAGS)

clean:
	-rm -rf $(OBJ) .Depend

.Depend:
ifneq ($(MAKECMDGOALS),clean)
	@$(CC) $(CFLAGS) -MM -MT $(SRC:%.cpp=%) $(SRC) > .Depend
endif

-include .Depend
