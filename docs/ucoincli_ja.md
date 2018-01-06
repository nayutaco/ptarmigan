# ucoincli

## NAME

`ucoincli` - control ucoin daemon

## SYNOPSIS

    ucoincli [options] [JSON-RPC port number]

### options

* `-h` : help
* `-q` : quit ucoind
* `-l` : list channels
* `-i [amount_msat]` : add invoice
* `-m` : list invoices
* `-p [pay config file],[payment_hash]`  : payment(need connected). if use `payment_hash`, `hash` is ignored in config file.
* `-c [peer config file]` : connect another node
* `-f [fund config file]` : open channel(need `-c` option)
* `-x` : close channel(need `-c` option)
* `-d [value]` : debug option
* `-g` : get commitment transaction(need `-c` option)

## DESCRIPTION

Control `ucoind`.  
`ucoincli` and `ucoind` are connect with TCP JSON-RPC(not HTTP).

### Configuration File Format

* peer config file format

```text
ipaddr=[IPv4 address]
port=[socket number]
node_id=[node pubkey]
```

* fund config file format

```text
txid=[fund-in txid]
txindex=[fund-in outpoint index]
signaddr=[address for sign funding transaction(internally use `bitcoin-cli dumpprivkey`)]
funding_sat=[funding satoshis in txid amount]
push_sat=[push satoshis for peer node]
```

* pay config file format

```text
hop_num=[below route num]
route0=[`own node_id`,`short_channel_id`,`msat`,`cltv_expiry`]
route1=[next `node_id`,next `short_channel_id`,`msat`,`cltv_expiry`]
...
```

### Command and JSON-RPC command

#### funding

```bash
ucoincli -c peer.conf -f fund.conf 9736
```

```json
{
    "method":"fund",
    "params":[
        "02f5fa009cbf9774960d5f5591a37fd931fe4a22563b7cfbf57d3f9a98b0e11882",
        "127.0.0.1",
        3333,
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
ucoincli -c peer.conf 9736
```

```json
{
    "method":"connect",
    "params":[
        "02f5fa009cbf9774960d5f5591a37fd931fe4a22563b7cfbf57d3f9a98b0e11882","127.0.0.1",
        3333
    ]
}
```

#### add invoice

```bash
ucoincli -i 123000 9736
```

```json
{
    "method":"invoice",
    "params":[ 123000 ]
}
```

#### getinfo

```bash
ucoincli -l 9736
```

```json
{
    "method":"getinfo",
    "params":[]
}
```

#### listinvoice

```bash
ucoincli -m 9736
```

```json
{
    "method":"listinvoice",
    "params":[]
}
```

#### payment

```bash
ucoincli -p pay.conf,112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00 9736
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