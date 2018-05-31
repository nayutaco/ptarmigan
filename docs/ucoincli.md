# ucoincli

## NAME

`ucoincli` - control ucoin daemon

## SYNOPSIS

```bash
ucoincli [options] [JSON-RPC port number]
```

* It can be omitted if the JSON-RPC port number is 9736 (`ucoind` port number is 9735).

### options

* single command
  * `-h` : help
  * `-q` : quit ucoind

* connect peer
  * `-c PEER_CONFIG_FILE` : new connection or already connected node
  * `-c NODE_ID@IPADDR:PORT` : new connection or already connected node
  * `-c NODE_ID` : already connected node

* information
  * `-l` : get information
  * `-m` : list invoices

* funding
  * `-f FUND_CONFIG_FILE` : open channel(need `-c` option)

* payment
  * `-i AMOUNT_MSAT` : add invoice
  * `-e PAYMENT_HASH` : erase a payment_hash
  * `-e ALL` : erase all payment_hashs
  * `-R BOLT11_INVOICE[,ADD_AMOUNT_MSAT]`  : payment with BOLT11 invoice format(keep temporary fail node list)
  * `-r BOLT11_INVOICE[,ADD_AMOUNT_MSAT]`  : payment with BOLT11 invoice format(clear temporary fail node list)
    * `ucoind` save fail node in DB if payment route return error for route skip.

* fee
  * `--setfeerate FEERATE_PER_KW` : set feerate_per_kw
    * if set not 0 value, send `update_fee`

* `-x` : close channel(need `-c` option)

* debug
  * `-d DECIMAL_VALUE` : debug option
  * `-c NODE_ID -g` : get commitment transaction

* port
  * default port number is 9736

## DESCRIPTION

Control `ucoind`.  
`ucoincli` and `ucoind` are connect with TCP JSON-RPC(not HTTP).

### Configuration File Format

* peer config file format (`-c`)

```text
node_id=[node pubkey]
ipaddr=[IPv4 address]
port=[port number]
```

* fund config file format (`-f`)

```text
txid=[fund-in txid]
txindex=[fund-in outpoint index]
signaddr=[address for sign funding transaction(internally use `bitcoin-cli dumpprivkey`)]
funding_sat=[funding satoshis in txid amount]
push_sat=[push satoshis for peer node]
feerate_per_kw=[feerate_per_kw for `open_channel`]
```

### Command and JSON-RPC command

#### funding

```bash
ucoincli -c peer.conf -f fund.conf
```

```json
{
    "method":"fund",
    "params":[
        "02f5fa009cbf9774960d5f5591a37fd931fe4a22563b7cfbf57d3f9a98b0e11882",
        "127.0.0.1",
        9735,
        "c165fed21602822ccad2f2394cfb8054e3c0c03620ab332b8f9bcad21c38e902",
        1,
        "mtkpsxCZhYmwGffbE2Rkj3DUcbrX8rJzfR",
        600000,
        300000
    ]
}
```

#### connect

```bash
ucoincli -c peer.conf
```

```json
{
    "method":"connect",
    "params":[
        "02f5fa009cbf9774960d5f5591a37fd931fe4a22563b7cfbf57d3f9a98b0e11882","127.0.0.1",
        9735
    ]
}
```

#### add invoice

```bash
ucoincli -i 123000
```

```json
{
    "method":"invoice",
    "params":[ 123000 ]
}
```

#### getinfo

```bash
ucoincli -l
```

```json
{
    "method":"getinfo",
    "params":[]
}
```

#### listinvoice

```bash
ucoincli -m
```

```json
{
    "method":"listinvoice",
    "params":[]
}
```

#### payment

```bash
ucoincli -r lntb1u1pdgjjwwpp50h7wjfp56ye392ajz82grpkeyerkh9ssaq9z7pgceqfkj8enugvqdyu0v3xgg36yffx2ctyypqhyarfvdkx2w3qfa6xsetjypcxcctrv4ejqar0yp6x2um5ypehqetwv35kueeqwdhjytpzdy3r5g3h8p3kzepcve3z6dekxgcz6dpnxgmj6wfexycz6ef4vgur2dmrvcmxzdtzyf7scqzysq5h93u4m2mcmn0yy4dr7rlwdnt57s9777rduwjnr6my0acf23wdnk8quh5ewyw4t6gmqd05lwlpp57uzvljjcc2sm2vwzxsy40adyfqqgv3djj
```

```json
{
    "method": "routepay",
    "params": [
        "lntb1u1pdgjjwwpp50h7wjfp56ye392ajz82grpkeyerkh9ssaq9z7pgceqfkj8enugvqdyu0v3xgg36yffx2ctyypqhyarfvdkx2w3qfa6xsetjypcxcctrv4ejqar0yp6x2um5ypehqetwv35kueeqwdhjytpzdy3r5g3h8p3kzepcve3z6dekxgcz6dpnxgmj6wfexycz6ef4vgur2dmrvcmxzdtzyf7scqzysq5h93u4m2mcmn0yy4dr7rlwdnt57s9777rduwjnr6my0acf23wdnk8quh5ewyw4t6gmqd05lwlpp57uzvljjcc2sm2vwzxsy40adyfqqgv3djj",
        0
    ]
}
```

## SEE ALSO

## AUTHOR

Nayuta Inc.