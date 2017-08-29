#ifndef NODEMNG_H__
#define NODEMNG_H__

#include <stdint.h>

/**************************************************************************
 * typedefs
 **************************************************************************/

struct node_t;


typedef struct {
    int             num;
    struct node_t   *p_node;
} nodemng_t;


/**************************************************************************
 * prototypes
 **************************************************************************/

int node_add(nodemng_t *pNodeMng, const uint8_t *pNodeId);
void node_free(nodemng_t *pNodeMng);
void node_dump(const nodemng_t *pNodeMng, int Index);
const uint8_t *node_get(const nodemng_t *pNodeMng, int Index);
int node_max(const nodemng_t *pNodeMng);

#endif /* NODEMNG_H__ */
