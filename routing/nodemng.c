#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "nodemng.h"


/**************************************************************************
 * macros
 **************************************************************************/

#define SZ_PUBKEY           (33)


/**************************************************************************
 * typedefs
 **************************************************************************/

typedef struct node_t {
    int             index;
    const uint8_t   *p_node_id;
} node_t;


/**************************************************************************
 * public functions
 **************************************************************************/

int node_add(nodemng_t *pNodeMng, const uint8_t *pNodeId)
{
    for (int lp = 0; lp < pNodeMng->num; lp++) {
        if (memcmp(pNodeMng->p_node[lp].p_node_id, pNodeId, SZ_PUBKEY) == 0) {
            return lp;
        }
    }

    pNodeMng->num++;
    pNodeMng->p_node = (node_t *)realloc(pNodeMng->p_node, sizeof(node_t) * pNodeMng->num);
    node_t *p = &pNodeMng->p_node[pNodeMng->num - 1];
    p->index = pNodeMng->num - 1;
    p->p_node_id = pNodeId;
    return p->index;
}


void node_free(nodemng_t *pNodeMng)
{
    free(pNodeMng->p_node);
    memset(pNodeMng, 0, sizeof(nodemng_t));
}


void node_dump(const nodemng_t *pNodeMng, int Index)
{
    printf(" [%d]", Index);
    for (int lp = 0; lp < SZ_PUBKEY; lp++) {
        printf("%02x", pNodeMng->p_node[Index].p_node_id[lp]);
    }
    printf("\n");
}


const uint8_t *node_get(const nodemng_t *pNodeMng, int Index)
{
    return pNodeMng->p_node[Index].p_node_id;
}


int node_max(const nodemng_t *pNodeMng)
{
    return pNodeMng->num;
}
