# ptarmd

## NAME

`ptarmd` - ptarm daemon

## SYNOPSIS

```bash
ptarmd [--network=NETWORK] [-p PORT] [-n ALIAS NAME] [-a IPv4 ADDRESS] [-c BITCOIN.CONF]
```

### options

* --network=NETWORK
  * blockchain name(mainnet, testnet, regtest)
    * default: mainnet

* --port=PORT
  * port number
    * default: 9735(if DB don't have data)
  * _NOTICE_: this value is witten to DB at first time

* --rpcport=PORT
  * RPC port number
    * default: node port + 1

* --alias=ALIAS_NAME
  * node alias name
    * default: `node_` + node_id first 6byte(if DB don't have data)
  * _NOTICE_: this value is witten to DB at first time

* --announceip=IPv4_ADDRESS
  * node announcement ip address
    * default: no ip address(if DB don't have data)
  * _NOTICE_: this value is witten to DB at first time

* --color=RRGGBB
  * node color
    * default: 000000(black)

* --conf=BITCOIN.CONF
  * current bitcoin.conf
  * read `rpcuser`, `rpcpassword` and `rpcport`.
    * if no `rpcuser` or `rpcpassword`, read from ~/.bitcoin/bitcoin.conf
    * if no `rpcport`, use default rpc port number(mainnet=8332, testnet=18332, regtest=18443)

* --bitcoinrpcuser=USERNAME
  * bitcoin RPC username
    * default: read from bitcoin.conf

* --bitcoinrpcpassword=PASSWORD
  * bitcoin RPC password
    * default: read from bitcoin.conf

* --bitcoinrpcport=PORT
  * bitcoin RPC port
    * default: read from bitcoin.conf

* --datadir=DATA_DIR
  * working directory
    * default: current directory

* -v
  * show using libraries

## DESCRIPTION

Start ptarm lightning daemon.

### related config file

* announcement config file(`anno.conf`) format

```text
cltv_expiry_delta=[(channel_update) cltv_expiry_delta]
htlc_minimum_msat=[(channel_update) htlc_minimum_msat]
fee_base_msat=[(channel_update) fee_base_msat]
fee_prop_millionths=[(channel_update) fee_prop_millionths]
```

* channel config file(`channel.conf`) format

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
