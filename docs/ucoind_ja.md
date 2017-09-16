ucoind
====

# NAME

`ucoind` - ucoin daemon


# SYNOPSIS

    ucoind [node config file] [options]


## options :

    `id`  : show own node_id(only read config file)
    `wif` : create WIF format string(random 32byte)


# DESCRIPTION

Start ucoin lightning daemon.

* node config file format

    port=[TCP socket number]  
    name=[alias name for node_announcement]  
    wif=[node private key(WIF format)]  
    _ipv4=[node IPv4 Address]_  
    _rpcuser=[JSON-RPC username]_  
    _rpcpasswd=[JSON-RPC password]_  
    _rpcurl=[JSON-RPC URL]_  

if not exist ipv4, `address descriptor` in `node_announcement` is 0.  
if not exist rpcxxx, read from `~/.bitcoin/bitcoin.conf`.


# SEE ALSO


# AUTHOR
    Nayuta Inc.

