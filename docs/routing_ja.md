# routing

## NAME

`routing` - calculate payment route

## SYNOPSIS

* create node graph

```bash
routing <db dir>
```

* create payment route(CSV format)

```bash
routing <db dir> <payer node_id> <payee node_id> <amount msat> [<min_final_cltv_expiry>]
```

* create payment route(JSON format)

```bash
routing <db dir> <payer node_id> <payee node_id> <amount msat> <min_final_cltv_expiry> <payment_hash>
```

## DESCRIPTION

Calculate payment route using dijkstra shortest path.  
This output is same as pay config file format(`ucoincli -p`).

## SEE ALSO

## AUTHOR

Nayuta Inc.
