#ifndef P2P_CLI_H__
#define P2P_CLI_H__

#include <stdint.h>

#include "lnapp.h"


/********************************************************************
 * prototypes
 ********************************************************************/

void p2p_cli_init(void);
void p2p_cli_start(my_daemoncmd_t Cmd, const daemon_connect_t *pConn, void *pParam, char *pResMsg);
void p2p_cli_stop_all(void);
lnapp_conf_t *p2p_cli_search_node(const uint8_t *pNodeId);
lnapp_conf_t *p2p_cli_search_short_channel_id(uint64_t short_channel_id);
void p2p_cli_show_self(char *pResMsg);
bool p2p_cli_is_looping(void);

#endif /* P2P_CLI_H__ */
