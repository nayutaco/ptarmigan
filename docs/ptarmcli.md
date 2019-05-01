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
  * `--help` : help
  * `--stop` : quit ptarmd

* connect peer
  * `-c NODE_ID@IPADDR:PORT` : new connection or already connected node
    * get all channel information from peer with `--initroutesync`

* information
  * `--getinfo` : get information

* funding
  * `-f FUND_CONFIG_FILE` : open channel(need `-c` option)
    * FUND_CONFIG_FILE can create by `pay_fundin.py`

* invoice
  * `--addinvoice=AMOUNT_MSAT` : add invoice
  * `--listinvoice` : list invoices
  * `--removeinvoice=PAYMENT_HASH` : erase a payment_hash
  * `--removeinvoice=ALL` : erase all payment_hashs

* payment
  * `--sendpayment BOLT11_INVOICE[,ADD_AMOUNT_MSAT]` : payment with BOLT11 invoice format
  * `--listpayment` : list payments
  * `--listpayment=PAYMENT_ID` : list specified payment
  * `--removepayment=PAYMENT_ID` : remove a payment from the payment list

* fee
  * `--setfeerate=FEERATE_PER_KW` : set feerate_per_kw
    * if set not 0 value, send `update_fee`

* close channel
  * `-x` : mutual close(need `-c` option)
  * `-xforce` : unilateral close(need `-c` option)

<!--
* debug
  * `--debug DECIMAL_VALUE` : debug option
  * `-c NODE_ID -g` : get commitment transaction and HTLC transaction
-->

* port
  * default port number is 9736

## DESCRIPTION

Control `ptarmd`.  
`ptarmcli` and `ptarmd` are connect with TCP JSON-RPC(not HTTP).

### Configuration File Format

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
ptarmcli -c 02f5fa009cbf9774960d5f5591a37fd931fe4a22563b7cfbf57d3f9a98b0e11882@127.0.0.1:9735
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
For funding, it needs a config file.

```bash
../pay_fundin.py 1000000 50000 

[FeeRate] 0.00001000
[Size] 167 bytes
[Send] 0.01000227 btc
[Address] 2NCvy3cefpVHBGrjC6RgAJPCZZEeLpvvYcE
[TXID] 04c7fe01a3721ebb0ab417dad804b22ad7aebd812bd81c5141ede9ff8645cd17
[LOCK] True
[CREATE] fund_20190415053538.conf

----
cat fund_20190415053538.conf

txid=04c7fe01a3721ebb0ab417dad804b22ad7aebd812bd81c5141ede9ff8645cd17
txindex=0
signaddr=2NCvy3cefpVHBGrjC6RgAJPCZZEeLpvvYcE
funding_sat=1000000
push_msat=50000
feerate_per_kw=0
----

ptarmcli -c 028df7753f0802ec2b781ffd44da838b7b57baebe2930132411fded4399e33bf58 -f fund_20190415053538.conf

```

```json
{
    "method": "fund",
    "params": [
        "028df7753f0802ec2b781ffd44da838b7b57baebe2930132411fded4399e33bf58",
        "0.0.0.0",
        0,
        "04c7fe01a3721ebb0ab417dad804b22ad7aebd812bd81c5141ede9ff8645cd17",
        0,
        1000000,
        50000,
        0,
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
    "params":[ 
                123000,
                0
             ]
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