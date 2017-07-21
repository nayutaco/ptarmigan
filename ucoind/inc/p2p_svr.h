#ifndef P2P_SVR_H__
#define P2P_SVR_H__

#include <stdint.h>

#include "lnapp.h"


/********************************************************************
 * prototypes
 ********************************************************************/

void *p2p_svr_start(void *pArg);
void p2p_svr_stop_all(void);
lnapp_conf_t *p2p_svr_search_node(const uint8_t *pNodeId);
lnapp_conf_t *p2p_svr_search_short_channel_id(uint64_t short_channel_id);
void p2p_svr_show_self(char *pResMsg);
bool p2p_svr_is_looping(void);

#endif /* P2P_SVR_H__ */
