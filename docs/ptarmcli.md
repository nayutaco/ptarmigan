# ptarmcli

## NAME

`ptarmcli` - control ptarm daemon

## SYNOPSIS

```bash
ptarmcli [options] [JSON-RPC port number]
```

* It can be omitted if the JSON-RPC port number is 9736 (`ptarmd` port number is 9735).

### options

* single command
  * `-h` : help
  * `-q` : quit ptarmd

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
    * `ptarmd` save fail node in DB if payment route return error for route skip.

* fee
  * `--setfeerate FEERATE_PER_KW` : set feerate_per_kw
    * if set not 0 value, send `update_fee`

* `-x` : close channel(need `-c` option)

* debug
  * `-d DECIMAL_VALUE` : debug option
  * `-c NODE_ID -g` : get commitment transaction and HTLC transaction

* port
  * default port number is 9736

## DESCRIPTION

Control `ptarmd`.  
`ptarmcli` and `ptarmd` are connect with TCP JSON-RPC(not HTTP).

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
funding_sat=[funding satoshis in txid amount]
push_sat=[push satoshis for peer node]
feerate_per_kw=[feerate_per_kw for `open_channel`]
```

### Command and JSON-RPC command

#### connect

```bash
ptarmcli -c PEER_NODE_ID@IP_ADDR:PORT
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

#### funding

```bash
../pay_fundin.sh 10000 8000 4000

----
cat fund.conf

txid=9a7b4456d7c2758540127d0401a75c5064b1f46f36aada499d5c85fcbd5dd782
txindex=0
signaddr=2NF8JohaX34qZV4mKZmZk17CcDMtbutF2fc
funding_sat=8000
push_sat=4000
feerate_per_kw=0
----

ptarmcli -c 028df7753f0802ec2b781ffd44da838b7b57baebe2930132411fded4399e33bf58 -f fund.conf
```

```json
{
    "method": "fund",
    "params": [
        "028df7753f0802ec2b781ffd44da838b7b57baebe2930132411fded4399e33bf58",
        "0.0.0.0",
        0,
        "9a7b4456d7c2758540127d0401a75c5064b1f46f36aada499d5c85fcbd5dd782",
        0,
        8000,
        4000,
        0
    ]
}
```

#### add invoice

```bash
ptarmcli -i 123000
```

```json
{
    "method":"invoice",
    "params":[ 123000 ]
}
```

#### getinfo

```bash
ptarmcli -l
```

```json
{
    "method":"getinfo",
    "params":[]
}
```

#### listinvoice

```bash
ptarmcli -m
```

```json
{
    "result": [
        {
            "hash": "dad73e2825409b41c6eeb125706cb7a16b66104515ab53692fffedf2248663be",
            "amount_msat": 2000,
            "creation_time": "2018/09/07 00:34:48",
            "expiry": 3600
        },
        {
            "hash": "638588558bbe5c047576a5ce531ffe6031b0974b7cb95d34fcffc9336bc2bed1",
            "amount_msat": 1000,
            "creation_time": "2018/09/07 00:34:45",
            "expiry": 3600
        }
    ]
}
```

#### payment

```bash
ptarmcli -r lntb1u1pdgjjwwpp50h7wjfp56ye392ajz82grpkeyerkh9ssaq9z7pgceqfkj8enugvqdyu0v3xgg36yffx2ctyypqhyarfvdkx2w3qfa6xsetjypcxcctrv4ejqar0yp6x2um5ypehqetwv35kueeqwdhjytpzdy3r5g3h8p3kzepcve3z6dekxgcz6dpnxgmj6wfexycz6ef4vgur2dmrvcmxzdtzyf7scqzysq5h93u4m2mcmn0yy4dr7rlwdnt57s9777rduwjnr6my0acf23wdnk8quh5ewyw4t6gmqd05lwlpp57uzvljjcc2sm2vwzxsy40adyfqqgv3djj
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