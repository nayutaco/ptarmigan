# ucoind

## NAME

`ucoind` - ucoin daemon

## SYNOPSIS

```bash
ucoind [-p PORT] [-n ALIAS NAME] [-a IPv4 ADDRESS] [-c BITCOIN.CONF] [-i]
```

### options

* -p PORT
  * port number
    * default: 9735(if DB don't have data)
  * _NOTICE_: this value is witten to DB at first time

* -n ALIAS_NAME
  * node alias name
    * default: `node_` + node_id first 6byte(if DB don't have data)
  * _NOTICE_: this value is witten to DB at first time

* -a IPv4_ADDRESS
  * node announcement ip address
    * default: no ip address(if DB don't have data)
  * _NOTICE_: this value is witten to DB at first time

* -c BITCOIN.CONF
  * current bitcoin.conf
    * default: ~/.bitcoin/bitcoin.conf

* -x
  * erase current DB(without node_id)(TEST)

* -N
  * erase node_announcement DB(TEST)

## DESCRIPTION

Start ucoin lightning daemon.

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
