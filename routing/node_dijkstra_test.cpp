// http://www.boost.org/doc/libs/1_65_0/libs/graph/example/dijkstra-example.cpp

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include <boost/config.hpp>
#include <iostream>
#include <fstream>
#include <vector>

#include <boost/graph/graph_traits.hpp>
#include <boost/graph/adjacency_list.hpp>
#include <boost/graph/dijkstra_shortest_paths.hpp>
#include <boost/property_map/property_map.hpp>

#include "nodemng.h"

using namespace boost;

/**************************************************************************
 * tests
 **************************************************************************/
namespace {
    //char name(int Edge)
    //{
    //    return (char)('A' + Edge);
    //}

    const uint8_t* name(const nodemng_t* pNodeMng, int Edge)
    {
        return node_get(pNodeMng, Edge);
    }
}


int main()
{
    typedef adjacency_list <
                    listS,
                    vecS,
                    undirectedS,
                    no_property,
                    property < edge_weight_t, int >
            > graph_t;
    typedef graph_traits < graph_t >::vertex_descriptor vertex_descriptor;
    typedef std::pair<int, int> Edge;


    const uint8_t node_a[] = {
        0x02, 0x54, 0x83, 0x3a, 0x4e, 0xfa, 0xf8, 0xf8,
        0x3a, 0xc6, 0xb2, 0xea, 0x9e, 0x78, 0x45, 0x68,
        0x76, 0x03, 0xe4, 0xf2, 0x6d, 0xfd, 0x86, 0x1f,
        0x20, 0xf3, 0x0c, 0xb2, 0x65, 0x3b, 0x67, 0x93,
        0xd0,
    };
    const uint8_t node_b[] = {
        0x03, 0x24, 0x80, 0xfb, 0x0b, 0x2d, 0xfd, 0xc6,
        0x2b, 0x99, 0x1f, 0x5f, 0x72, 0x2f, 0xce, 0x66,
        0x62, 0x66, 0xd7, 0x91, 0x72, 0x2e, 0x9b, 0xf3,
        0x8c, 0xf3, 0xcb, 0x7a, 0xe0, 0x4a, 0x57, 0x6d,
        0x02,
    };
    const uint8_t node_c[] = {
        0x02, 0x55, 0x53, 0x3e, 0xb6, 0x65, 0x10, 0x84,
        0x11, 0xab, 0x48, 0xcf, 0xc3, 0x8c, 0xe1, 0xc9,
        0x9b, 0xf2, 0xb5, 0xb4, 0xbd, 0xa9, 0xa1, 0x05,
        0x73, 0x4f, 0x74, 0xdc, 0xde, 0x02, 0xdf, 0xe2,
        0x18,
    };
    const uint8_t node_d[] = {
        0x02, 0x47, 0xe3, 0xb4, 0xce, 0xc1, 0xea, 0xd6,
        0x86, 0x23, 0x8b, 0x91, 0x73, 0x2d, 0x47, 0x66,
        0xfb, 0x95, 0xe4, 0x39, 0x48, 0x16, 0x62, 0x08,
        0x3a, 0xf8, 0x95, 0x17, 0x8d, 0xe6, 0x15, 0x73,
        0x19,
    };

    nodemng_t nodemng = {0};
    int node_a_idx = node_add(&nodemng, node_a);
    int node_b_idx = node_add(&nodemng, node_b);
    int node_c_idx = node_add(&nodemng, node_c);
    int node_d_idx = node_add(&nodemng, node_d);
    int node_b_idx2 = node_add(&nodemng, node_b);
    assert(node_b_idx == node_b_idx2);      //重複登録しない
    int num_nodes = node_max(&nodemng);

    /*
     * a--b--c
     * |
     * d
     */

    //channel
    std::vector<Edge> edge_array;
    edge_array.push_back(Edge(node_a_idx, node_b_idx));
    edge_array.push_back(Edge(node_b_idx, node_c_idx));
    edge_array.push_back(Edge(node_a_idx, node_d_idx));

    //weight
    std::vector<int> weights;
    weights.push_back(1);
    weights.push_back(1);
    weights.push_back(1);

    //start/goal point
    int sp = node_d_idx;
    int gp = node_c_idx;

    graph_t g(edge_array.begin(), edge_array.end(), weights.begin(), num_nodes);

    property_map<graph_t, edge_weight_t>::type weightmap = get(edge_weight, g);
    std::vector<vertex_descriptor> p(num_vertices(g));
    std::vector<int> d(num_vertices(g));
    dijkstra_shortest_paths(g, vertex(sp, g),
            predecessor_map(boost::make_iterator_property_map(p.begin(), get(boost::vertex_index, g))).
            distance_map(boost::make_iterator_property_map(d.begin(), get(boost::vertex_index, g))));

    if (p[vertex(gp, g)] == vertex(gp, g)) {
        std::cout << "no route" << std::endl;
        return -1;
    }

    //逆順に入っているので、並べ直す
    std::deque<vertex_descriptor> route;        //std::vectorにはpush_front()がない
    for (vertex_descriptor v = vertex(gp, g); v != vertex(sp, g); v = p[v]) {
        route.push_front(v);
    }
    route.push_front(vertex(sp, g));

    std::deque<vertex_descriptor>::iterator it = route.begin();
    while (it != route.end()) {
        node_dump(&nodemng, *it);
        it++;
    }

    //std::cout << "distances and parents:" << std::endl;
    //graph_traits < graph_t >::vertex_iterator vi, vend;
    //for (boost::tie(vi, vend) = vertices(g); vi != vend; ++vi) {
    //    std::cout << "distance(" << name(*vi) << ") = " << d[*vi] << ", ";
    //    std::cout << "parent(" << name(*vi) << ") = " << name(p[*vi]) << std::endl;
    //}
    //std::cout << std::endl;


    //////////////////////////////////////////////////////////////
    std::ofstream dot_file("figs/tst.dot");

    dot_file << "digraph D {\n"
             << "  rankdir=LR\n"
             << "  size=\"4,3\"\n"
             << "  ratio=\"fill\"\n"
             << "  edge[style=\"bold\"]\n" << "  node[shape=\"circle\"]\n";

    graph_traits < graph_t >::edge_iterator ei, ei_end;
    for (boost::tie(ei, ei_end) = edges(g); ei != ei_end; ++ei) {
        graph_traits < graph_t >::edge_descriptor e = *ei;
        graph_traits < graph_t >::vertex_descriptor u = source(e, g), v = target(e, g);
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
        dot_file << "]";
    }
    dot_file << "}";
    //////////////////////////////////////////////////////////////


    node_free(&nodemng);

    return 0;
}
