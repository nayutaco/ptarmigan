ucoind
====

## NAME

`ucoind` - ucoin daemon

## SYNOPSIS

    ucoind [node config file] [options]

### options

    `id`  : show own node_id(only read config file)
    `wif` : create WIF format string(random 32byte)

## DESCRIPTION

Start ucoin lightning daemon.

* node config file format

    port=[TCP socket number]  
    name=[alias name for node_announcement]  
    wif=[node private key(WIF format)]  
    _ipv4=[node IPv4 Address]_  
    _rpcuser=[JSON-RPC username]_  
    _rpcpasswd=[JSON-RPC password]_  
    _rpcurl=[JSON-RPC URL]_  
    _rpcport=[JSON-RPC port number]_  

if not exist ipv4, `address descriptor` in `node_announcement` is 0.  
if not exist rpcxxx, read from `~/.bitcoin/bitcoin.conf`.

### other config file

If `anno.conf` is exist same folder, 

* announcement config file format

    cltv_expiry_delta=[_(channel_update)_ cltv_expiry_delta]  
    htlc_minimum_msat=[_(channel_update)_ htlc_minimum_msat]  
    fee_base_msat=[_(channel_update)_ fee_base_msat]  
    fee_prop_millionths=[_(channel_update)_ fee_prop_millionths]  



## SEE ALSO

## AUTHOR
    Nayuta Inc.

