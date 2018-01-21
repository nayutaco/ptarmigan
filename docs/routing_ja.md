# routing

## NAME

`routing` - calculate payment route

## SYNOPSIS

* create node graph

```bash
routing [mainnet/testnet/regtest] [db dir]
```

* create payment route

```bash
routing [mainnet/testnet/regtest] [db dir] [payer node_id] [payee node_id] [amount msat] <[min_final_cltv_expiry]>
```

## DESCRIPTION

Calculate payment route using dijkstra shortest path.  
This output is same as pay config file format(`ucoincli -p`).

## SEE ALSO

## AUTHOR

Nayuta Inc.
