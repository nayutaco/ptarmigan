# routing

## NAME

`routing` - calculate payment route

## SYNOPSIS

```bash
routing -s PAYER_NODEID -r PAYEE_NODEID -d DB_DIR -a AMOUNT_MSAT -e MIN_FINAL_CLTV_EXPIRY -p PAYMENT_HASH [-j]
```

### options

* -s PAYER_NODEID
  * payer node_id

* -r PAYEE_NODEID
  * payee node_id

* -d DB_DIR
  * DB directory
    * default: `./dbucoin`

* -a AMOUNT_MSAT
  * amount_msat
    * default: `0`

* -e MIN_FINAL_CLTV_EXPIRY
  * min_final_cltv_expiry
    * default: `9`

* -p PAYMENT_HASH
  * payment_hash
    * default: none

* -j
  * output JSON format
    * default: CSV format
  * _NOTE_ : need PAYMENT_HASH if `-j` set

* -c
  * clear routing skip channel list
  * _NOTE_ : need restart `ucoind`

## DESCRIPTION

Calculate payment route using dijkstra shortest path.  
This output is same as pay config file format(`ucoincli -p`).

## SEE ALSO

## AUTHOR

Nayuta Inc.
