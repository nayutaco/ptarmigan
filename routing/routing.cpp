// http://www.boost.org/doc/libs/1_65_0/libs/graph/example/dijkstra-example.cpp

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <stdbool.h>
#include <unistd.h>
#include <pthread.h>
#include <poll.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <assert.h>

//#define M_DEBUG
//#define M_NO_GRAPH

#define UCOIN_USE_PRINTFUNC
#include "ucoind.h"
#include "ln_db.h"
#include "ln_db_lmdb.h"
#include "nodemng.h"
#include "conf.h"

#include <iostream>
#include <fstream>
#include <deque>
#include <vector>

#include <boost/config.hpp>
#include <boost/graph/adjacency_list.hpp>
#include <boost/graph/dijkstra_shortest_paths.hpp>
#include <boost/graph/graph_traits.hpp>
#include <boost/property_map/property_map.hpp>


using namespace boost;

/**************************************************************************
 * macros
 **************************************************************************/

#define MSGTYPE_CHANNEL_ANNOUNCEMENT        ((uint16_t)0x0100)
#define MSGTYPE_NODE_ANNOUNCEMENT           ((uint16_t)0x0101)
#define MSGTYPE_CHANNEL_UPDATE              ((uint16_t)0x0102)
#define MSGTYPE_ANNOUNCEMENT_SIGNATURES     ((uint16_t)0x0103)


/**************************************************************************
 * prototypes
 **************************************************************************/

extern "C" {
    void ln_print_announce(const uint8_t *pData, uint16_t Len);
    bool ln_getids_cnl_anno(uint64_t *p_short_channel_id, uint8_t *pNodeId1, uint8_t *pNodeId2, const uint8_t *pData, uint16_t Len);
}


/********************************************************************
 * static variables
 ********************************************************************/

static MDB_env      *mpDbEnv = NULL;
static struct nodes_t {
    uint64_t short_channel_id;
    uint8_t node_id1[UCOIN_SZ_PUBKEY];
    uint8_t node_id2[UCOIN_SZ_PUBKEY];
} *mpNodes = NULL;
static int mNodeNum = 0;


/********************************************************************
 * misc
 ********************************************************************/

#ifndef M_NO_GRAPH
static const uint8_t* name(const nodemng_t* pNodeMng, int Edge)
{
    return node_get(pNodeMng, Edge);
}
#endif


static void loadconf(const char* pConfFile, uint8_t* pPubKey)
{
    node_conf_t nconf;
    rpc_conf_t rconf;
    bool bret = load_node_conf(pConfFile, &nconf, &rconf);
    assert(bret);

    ucoin_init(UCOIN_TESTNET, true);
    ucoin_util_keys_t mykeys;
    bret = ucoin_util_wif2keys(&mykeys, nconf.wif);
    assert(bret);
    memcpy(pPubKey, mykeys.pub, UCOIN_SZ_PUBKEY);
    ucoin_term();
}


#ifdef M_DEBUG
static void dumpbin(const uint8_t *pData, uint16_t Len)
{
    for (uint16_t lp = 0; lp < Len; lp++) {
        printf("%02x", pData[lp]);
    }
    printf("\n");
}
#endif


/* Dump in BDB-compatible format */
static int dumpit(MDB_txn *txn, MDB_dbi dbi, const MDB_val *p_key)
{
    const char *name = (const char *)p_key->mv_data;

    if (strcmp(name, "channel_anno") == 0) {
        MDB_dbi     dbi;
        MDB_cursor  *cursor;

        //ここでdbi, txnを使ってcursorを取得
        int retval = mdb_dbi_open(txn, name, 0, &dbi);
        assert(retval == 0);
        retval = mdb_cursor_open(txn, dbi, &cursor);
        assert(retval == 0);
        int ret;

        do {
            uint64_t short_channel_id;
            char type;
            ucoin_buf_t buf;

            ucoin_buf_init(&buf);
            ret = ln_lmdb_load_anno_channel_cursor(cursor, &short_channel_id, &type, &buf);
            if (ret == 0) {
                if (type == LN_DB_CNLANNO_ANNO) {
                    mNodeNum++;
                    mpNodes = (struct nodes_t *)realloc(mpNodes, sizeof(struct nodes_t) * mNodeNum);

                    bool bret = ln_getids_cnl_anno(
                                        &mpNodes[mNodeNum - 1].short_channel_id,
                                        mpNodes[mNodeNum - 1].node_id1,
                                        mpNodes[mNodeNum - 1].node_id2,
                                        buf.buf, buf.len);
                    assert(bret);
                }
            }
            ucoin_buf_free(&buf);
        } while (ret == 0);
        mdb_cursor_close(cursor);
        mdb_close(mpDbEnv, dbi);
    }

    return 0;
}


static void loaddb(const char *pDbPath)
{
    int ret;
    MDB_txn     *txn;
    MDB_dbi     dbi;
    MDB_val     key;
    MDB_cursor  *cursor;

    ret = mdb_env_create(&mpDbEnv);
    assert(ret == 0);
    ret = mdb_env_set_maxdbs(mpDbEnv, 2);
    assert(ret == 0);
    ret = mdb_env_open(mpDbEnv, pDbPath, MDB_RDONLY, 0664);
    assert(ret == 0);

    ret = mdb_txn_begin(mpDbEnv, NULL, MDB_RDONLY, &txn);
    assert(ret == 0);
    ret = mdb_dbi_open(txn, NULL, 0, &dbi);
    assert(ret == 0);

    ret = mdb_cursor_open(txn, dbi, &cursor);
    assert(ret == 0);

    int list = 0;
    while ((ret = mdb_cursor_get(cursor, &key, NULL, MDB_NEXT_NODUP)) == 0) {
        MDB_dbi dbi2;
        if (memchr(key.mv_data, '\0', key.mv_size)) {
            continue;
        }
        ret = mdb_dbi_open(txn, (const char *)key.mv_data, 0, &dbi2);
        if (ret == 0) {
            if (list) {
                list++;
            } else {
                ret = dumpit(txn, dbi2, &key);
                if (ret) {
                    break;
                }
            }
            mdb_close(mpDbEnv, dbi2);
        } else {
            printf("???\n");
        }
    }
    mdb_cursor_close(cursor);
    mdb_close(mpDbEnv, dbi);
    mdb_txn_abort(txn);
    mdb_env_close(mpDbEnv);
}


/********************************************************************
 *
 ********************************************************************/

int main(int argc, char* argv[])
{
    bool ret;
    uint8_t my_nodeid[UCOIN_SZ_PUBKEY];
    uint8_t tgt_nodeid[UCOIN_SZ_PUBKEY];
    uint64_t amount;
    uint32_t cltv_expiry;

    if (argc != 6) {
        printf("usage:");
        printf("\t%s [db path] [node conf] [target node_id] [amount] [cltv_expiry]\n", argv[0]);
        return -1;
    }

    loaddb(argv[1]);

    loadconf(argv[2], my_nodeid);

    ret = misc_str2bin(tgt_nodeid, sizeof(tgt_nodeid), argv[3]);
    assert(ret);

    amount = (uint64_t)strtoull(argv[4], NULL, 10);

    cltv_expiry = (uint32_t)strtoul(argv[5], NULL, 10);

#ifdef M_DEBUG
    printf("wif: %s\n", nconf.wif);
    printf("my nodeid    : ");
    dumpbin(my_nodeid, UCOIN_SZ_PUBKEY);
    printf("target nodeid: ");
    dumpbin(tgt_nodeid, UCOIN_SZ_PUBKEY);
#endif

    typedef adjacency_list <
                    listS,
                    vecS,
                    bidirectionalS,
                    no_property,
                    property < edge_weight_t, int >
            > graph_t;
    typedef graph_traits < graph_t >::vertex_descriptor vertex_descriptor;
    typedef std::pair<int, int> Edge;


    nodemng_t nodemng = {0};
    std::vector<Edge> edge_array;
    std::vector<int> weights;
    int my_idx = -1;
    int tgt_idx = -1;


    //Edge追加
    edge_array.resize(mNodeNum);
    weights.resize(mNodeNum);
    for (int lp = 0; lp < mNodeNum; lp++) {
#ifdef M_DEBUG
        printf("  short_channel_id=%016" PRIx64 "\n", mpNodes[lp].short_channel_id);
        printf("    [1]");
        dumpbin(mpNodes[lp].node_id1, UCOIN_SZ_PUBKEY);
        printf("    [2]");
        dumpbin(mpNodes[lp].node_id2, UCOIN_SZ_PUBKEY);
        printf("\n");
#endif

        int idx1 = node_add(&nodemng, mpNodes[lp].node_id1);
        int idx2 = node_add(&nodemng, mpNodes[lp].node_id2);
        if (my_idx == -1) {
            if (memcmp(mpNodes[lp].node_id1, my_nodeid, UCOIN_SZ_PUBKEY) == 0) {
                my_idx = idx1;
            } else if (memcmp(mpNodes[lp].node_id2, my_nodeid, UCOIN_SZ_PUBKEY) == 0) {
                my_idx = idx2;
            }
        }
        if (tgt_idx == -1) {
            if (memcmp(mpNodes[lp].node_id1, tgt_nodeid, UCOIN_SZ_PUBKEY) == 0) {
                tgt_idx = idx1;
            } else if (memcmp(mpNodes[lp].node_id2, tgt_nodeid, UCOIN_SZ_PUBKEY) == 0) {
                tgt_idx = idx2;
            }
        }

        if (idx1 != idx2) {
            edge_array.push_back(Edge(idx1, idx2));
            weights.push_back(1);
            edge_array.push_back(Edge(idx2, idx1));
            weights.push_back(1);
        }
    }
    int num_nodes = node_max(&nodemng);

#ifdef M_DEBUG
    printf("my_idx=%d, tgt_idx=%d\n", my_idx, tgt_idx);
#endif
    if ((my_idx == -1) || (tgt_idx == -1)) {
        std::cout << "no start/goal node" << std::endl;
        return -1;
    }

    graph_t g(edge_array.begin(), edge_array.end(), weights.begin(), num_nodes);

    //start/goal point
    vertex_descriptor pnt_start = vertex(my_idx, g);
    vertex_descriptor pnt_goal = vertex(tgt_idx, g);

    property_map<graph_t, edge_weight_t>::type weightmap = get(edge_weight, g);
    std::vector<vertex_descriptor> p(num_vertices(g));      //parent
    std::vector<int> d(num_vertices(g));
    dijkstra_shortest_paths(g, pnt_start,
            predecessor_map(boost::make_iterator_property_map(p.begin(), get(boost::vertex_index, g))).
                distance_map(boost::make_iterator_property_map(d.begin(), get(boost::vertex_index, g))));

    if (p[pnt_goal] == pnt_goal) {
        std::cout << "no route" << std::endl;
        return -1;
    }

    //逆順に入っているので、並べ直す
    std::deque<vertex_descriptor> route;        //std::vectorにはpush_front()がない
    for (vertex_descriptor v = pnt_goal; v != pnt_start; v = p[v]) {
        route.push_front(v);
    }
    route.push_front(pnt_start);


    //pay.conf形式の出力
    int hop = (int)route.size();
    const uint8_t *p_next;
    printf("hop_num=%d\n", hop);
    for (int lp = 0; lp < hop - 1; lp++) {
        const uint8_t *p_now  = node_get(&nodemng, route[lp]);
        p_next = node_get(&nodemng, route[lp + 1]);
        if (lp != 0) {
#warning CLTVは暫定で-1していく。amountは同じにしている。
            cltv_expiry--;
        }

        int lp2;
        for (lp2 = 0; lp2 < UCOIN_SZ_PUBKEY; lp2++) {
            if (p_now[lp2] != p_next[lp2]) {
                break;
            }
        }
        const uint8_t *p_node_id1;
        const uint8_t *p_node_id2;
        if (p_now[lp2] < p_next[lp2]) {
            p_node_id1 = p_now;
            p_node_id2 = p_next;
        } else {
            p_node_id1 = p_next;
            p_node_id2 = p_now;
        }
        uint64_t sci = 0;
        for (int lp2 = 0; lp2 < mNodeNum; lp2++) {
            if ( (memcmp(p_node_id1, mpNodes[lp2].node_id1, UCOIN_SZ_PUBKEY) == 0) &&
                 (memcmp(p_node_id2, mpNodes[lp2].node_id2, UCOIN_SZ_PUBKEY) == 0) ) {
                sci = mpNodes[lp2].short_channel_id;
                break;
            }
        }

        for (int lp2 = 0; lp2 < UCOIN_SZ_PUBKEY; lp2++) {
            printf("%02x", p_now[lp2]);
        }
        printf(",%016" PRIx64 ",%" PRIu64 ",%" PRIu32 "\n", sci, amount, cltv_expiry);
    }

    //最後
    for (int lp2 = 0; lp2 < UCOIN_SZ_PUBKEY; lp2++) {
        printf("%02x", p_next[lp2]);
    }
    printf(",0,%" PRIu64 ",%" PRIu32 "\n", amount, cltv_expiry);


#ifndef M_NO_GRAPH
    //////////////////////////////////////////////////////////////
    std::ofstream dot_file("routing.dot");

    dot_file << "digraph D {\n"
             << "  rankdir=LR\n"
             << "  size=\"4,3\"\n"
             << "  ratio=\"fill\"\n"
             << "  edge[style=\"bold\"]\n" << "  node[shape=\"circle\"]\n";

    graph_traits < graph_t >::edge_iterator ei, ei_end;
    for (boost::tie(ei, ei_end) = edges(g); ei != ei_end; ++ei) {
        graph_traits < graph_t >::edge_descriptor e = *ei;
        graph_traits < graph_t >::vertex_descriptor u = source(e, g);
        graph_traits < graph_t >::vertex_descriptor v = target(e, g);
        if (u != v) {
            char node1[68];
            char node2[68];
            node1[0] = (char)('A' + u);
            node1[1] = '\0';
            node2[0] = (char)('A' + v);
            node2[1] = '\0';
            const uint8_t *p_node1 = name(&nodemng, u);
            const uint8_t *p_node2 = name(&nodemng, v);
            for (int lp = 0; lp < 3; lp++) {
                char s[3];
                sprintf(s, "%02x", p_node1[lp]);
                strcat(node1, s);
                sprintf(s, "%02x", p_node2[lp]);
                strcat(node2, s);
            }
            dot_file << node1 << " -> " << node2 << "[label=\"" << get(weightmap, e) << "\"";
            if (p[v] == u) {
                dot_file << ", color=\"black\"";
            } else {
                dot_file << ", color=\"grey\"";
            }
            dot_file << "]" << std::endl;
        }
    }
    dot_file << "}";
    //////////////////////////////////////////////////////////////
#endif

    node_free(&nodemng);

    return 0;
}
