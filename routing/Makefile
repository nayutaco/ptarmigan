all:
	g++ -Wall -ggdb -I../include -I../ucoin/include -I../ucoin/libs/install/include -o routing routing.cpp nodemng.c ../cmn/conf.c ../cmn/misc.c -L../libs/install/lib -L../ucoin/libs/install/lib -L../ucoin -llmdb -lucoin -lsodium -lbase58 -lmbedcrypto -pthread

test:
	g++ -ggdb -Wall -o tst node_dijkstra_test.cpp nodemng.c
	@-mkdir -p figs
	./tst
	@dot -T jpg figs/tst.dot -o graph.jpg
	@rm -rf figs tst

clean:
	rm -rf figs tst graph.jpg routing
