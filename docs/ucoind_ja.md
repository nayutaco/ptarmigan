# ucoind

## NAME

`ucoind` - ucoin daemon

## SYNOPSIS

    ucoind [node config file] [id]

### options

* `node config file` : node configuration file(detail below)
* `id` : show own node_id from DB

## DESCRIPTION

Start ucoin lightning daemon.  
First time(`dbucoin` DB directory not created), `node_id`, `name` and `port` are written in DB.  
After second time, `name` and `port` dont't reflect at node settings.


### node config file format

```text
port=[TCP socket number] (*first time)
name=[alias name for node_announcement] (*first time)
_ipv4=[node IPv4 Address]_
_rpcuser=[JSON-RPC username]_
_rpcpasswd=[JSON-RPC password]_
_rpcurl=[JSON-RPC URL]_
_rpcport=[JSON-RPC port number]_
```

If not exist ipv4, `address descriptor` in `node_announcement` is 0.  
If not exist rpcxxx, read from `~/.bitcoin/bitcoin.conf`.

### other config file

If `anno.conf` exists same folder, use it for announcement parameter.  
If `establish.conf` exists same folder, use it for establish parameter.  

* announcement config file(`anno.conf`) format

```text
cltv_expiry_delta=[_(channel_update)_ cltv_expiry_delta]
htlc_minimum_msat=[_(channel_update)_ htlc_minimum_msat]
fee_base_msat=[_(channel_update)_ fee_base_msat]
fee_prop_millionths=[_(channel_update)_ fee_prop_millionths]
```

* establish config file(establish.conf) format

```text
dust_limit_sat=[dust_lmit_satoshis]
max_htlc_value_in_flight_msat=[max_htlc_value_in_flight_msat]
channel_reserve_sat=[channel_reserve_satothis]
htlc_minimum_msat=[htlc_minimum_msat]
to_self_delay=[to_self_delay]
max_accepted_htlcs=[max_accepted_htlcs]
min_depth=[minimum_depth]
```

## SEE ALSO

## AUTHOR

Nayuta Inc.
