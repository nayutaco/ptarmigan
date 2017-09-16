ucoincli
====

# NAME

`ucoincli` - control ucoin daemon


# SYNOPSIS

    ucoincli [options] [JSON-RPC port number]


## options :

`-h` : help  
`-q` : quit ucoind  
`-l` : list channels  
`-i [amount]` : add invoice  
`-m` : list invoices  
`-c [peer config file]` : connect another node  
`-f [fund config file]` : open channel(need `-c` option)  
`-p [pay config file]`  : payment(need `-c` option)  
`-x` : close channel(need `-c` option)


# DESCRIPTION

Control `ucoind`.  
`ucoincli` and `ucoind` are connect with TCP JSON-RPC(not HTTP).


* peer config file format

    ipaddr=[IPv4 address]  
    port=[socket number]  
    node_id=[node pubkey]  

* fund config file format

    txid=[fund-in txid]  
    txindex=[fund-in outpoint index]  
    signaddr=[address for sign funding transaction(internally use `bitcoin-cli dumpprivkey`)]  
    funding_sat=[funding satoshis in txid amount]  
    push_sat=[push satoshis for peer node]

* pay config file format

    hash=[preimage hash from payee]  
    hop_num=[below route num]  
    route0=[`own node_id`,`short_channel_id`,`msat`,`cltv_expiry`]  
    route1=[next `node_id`,next `short_channel_id`,`msat`,`cltv_expiry`]  
    ...

# SEE ALSO


# AUTHOR
    Nayuta Inc.

