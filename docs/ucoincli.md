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
  * `-c [peer config file]` : new connection or already connected node
  * `-c [peer node_id]@[peer ipaddr]:port` : new connection or already connected node
  * `-c [connected node_id]` : already connected node

* information
  * `-l` : get information
  * `-m` : list invoices

* funding
  * `-f [fund config file]` : open channel(need `-c` option)

* payment
  * `-i [amount_msat]` : add invoice
  * `-e [payment_hash]` : erase a payment_hash
  * `-e ALL` : erase all payment_hashs
  * `-p [pay config file],[payment_hash]` : payment
  * `-r [BOLT11 invoice]`  : payment with BOLT11 invoice format

* `-x` : close channel(need `-c` option)

* debug
  * `-d [value]` : debug option
  * `-g` : get commitment transaction(need `-c` option)

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

* payment CSV config file format (`-p`)

```text
hop_num=[below route num]
route0=[`own node_id`,`short_channel_id`,`msat`,`cltv_expiry`]
route1=[next `node_id`,next `short_channel_id`,`msat`,`cltv_expiry`]
...
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
        "7dfce92434d13312abb211d48186d926476b9610e80a2f0518c813691f33e218", 
        100000, 
        "039cc950286a8fa99218283d1adc2456e0d5e81be558da77dd6e85ba9a1fff5ad3", 
        ""
    ]
}
```

----

```bash
ucoincli -p pay.conf,112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00
```

```json
{
    "method":"pay",
    "params":[
        "112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00",
        2, [
            [
                "02db26f12de34897655f33605435c1f0523904b1990e96f71b24ba07074aadb946",
                "1b10000020000",
                100000,
                9
            ],
            [
                "02f5fa009cbf9774960d5f5591a37fd931fe4a22563b7cfbf57d3f9a98b0e11882",
                "0",
                100000,
                9
            ]
        ]
    ]
}
```

## SEE ALSO

## AUTHOR

Nayuta Inc.