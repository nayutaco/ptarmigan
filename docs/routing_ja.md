routing
====

# NAME

`routing` - calculate payment route


# SYNOPSIS

* create node graph
```
routing [mainnet/testnet] [db dir]
```

* create payment route
```
routing [mainnet/testnet] [db dir] [node config file] [target node_id] [amount msat]
```


# DESCRIPTION

Calculate payment route using dijkstra shortest path.  
This output is same as pay config file format(`ucoincli -c -p`).


# SEE ALSO


# AUTHOR
    Nayuta Inc.

