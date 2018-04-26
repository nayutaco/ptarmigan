#ifndef LN_ROUTING_H__
#define LN_ROUTING_H__

#ifdef __cplusplus
extern "C" {
#endif  //__cplusplus

int ln_routing_calculate(
        const uint8_t *send_nodeid,
        const uint8_t *recv_nodeid,
        uint32_t cltv_expiry,
        uint64_t amtmsat,
        const char *payment_hash,
        const char *dbdir,
        bool clear_skip_db);

#ifdef __cplusplus
}
#endif  //__cplusplus

#endif /* LN_ROUTING_H__ */
