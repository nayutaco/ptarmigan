#ifndef P2P_COMMON_H__
#define P2P_COMMON_H__


/********************************************************************
 * macros
 ********************************************************************/

#define P2PCMD_INIT     ((uint16_t)0x0010)
#define P2PCMD_ERROR    ((uint16_t)0x0011)

//#define P2PCMD_     ((uint16_t)0x00)
//#define P2PCMD_     ((uint16_t)0x00)
//#define P2PCMD_     ((uint16_t)0x00)
//#define P2PCMD_     ((uint16_t)0x00)
//#define P2PCMD_     ((uint16_t)0x00)
//#define P2PCMD_     ((uint16_t)0x00)
//#define P2PCMD_     ((uint16_t)0x00)
//#define P2PCMD_     ((uint16_t)0x00)
//#define P2PCMD_     ((uint16_t)0x00)
//#define P2PCMD_     ((uint16_t)0x00)
//#define P2PCMD_     ((uint16_t)0x00)
//#define P2PCMD_     ((uint16_t)0x00)
//#define P2PCMD_     ((uint16_t)0x00)
//#define P2PCMD_     ((uint16_t)0x00)
//#define P2PCMD_     ((uint16_t)0x00)


/********************************************************************
 * macros functions
 ********************************************************************/


/********************************************************************
 * typedefs
 ********************************************************************/

typedef struct {
    uint8_t         status;

} p2p_status_t;

typedef struct {
    uint16_t        cmd;
    uint8_t         *pData;
    uint16_t        len;
} p2p_command_base_t;


/********************************************************************
 * prototypes
 ********************************************************************/

int p2p_cmd_send(int sock, const p2p_command_base_t *pCmd);
int p2p_cmd_process(const p2p_command_base_t *pCmd);


#endif /* P2P_COMMON_H__ */
