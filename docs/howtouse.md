# How to use

[Installation](INSTALL.md)

## start `ptarmd`(ptarmigan daemon)

* start `bitcoind` before starting `ptarmd`.

```text
rpcuser=bitcoinuser
rpcpassword=bitcoinpassword
server=1
txindex=1
testnet=1
```

* default behavior
  * work files: current directory
  * chain: mainnet
  * port: 9735
  * rpcport: 9736
  * alias: `node_` + node_id[0:6](like: `node_03a7f9dff5e6`)
  * color: #000000(black)
  * no IP address in `node_announcement`
  * bitcoind rpcuser/rpcpassword: read from `~/.bitcoin/bitcoin.conf`
  * [options...](ptarmd.md)

```bash
# create work folder
cd ptarmigan/install
./new_nodedir.sh [NODE_NAME]
cd [NODE_NAME]

# start with testnet!
../ptarmd --network=testnet
```

## daemon control `ptarmcli`(ptarmigan client)

* You can access to `ptarmd` with JSON-RPC or `ptarmcli`.
  * JSON-RPC uses TCP socket(not http/https)
* `ptarmcli` send/receive JSON-RPC TCP socket internal.
* You can omit `ptarmcli` rpcport option if..
  * `ptarmd` uses port 9735 and JRON-RPC port 9736.
  * in the same directory as `ptarmd` working directory.

### get information

Show my node information.

* my node_id
* channel amount
* connected peer

```bash
../ptarmcli --getinfo
```

### connect node

Connecting known lightning node, use `-c` command.
If you have channels, `ptarmd` try connect the peers automatically.

* node_id
* IP address(only IPv4)
* port number

```bash
# two connection method

# a. Only connect peer(not request peer's routing information)
../ptarmcli -c NODE_ID@IPv4_ADDRESS:PORT

# b. Get peer's all routing information by `--initroutesync`.
#    Routing information is used for payment.
#    (If you have already connected, disconnect and connect with `--initroutesync`.)
../ptarmcli -c NODE_ID@IPv4_ADDRESS:PORT --initroutesync
```

### open channel

After connecting, you can open channel with connection node.

```bash
# create funding file
# (this script use current bitcoind wallet.)
../pay_fundin.py AMOUNT_SAT
(create fund_xxxx.conf)

../ptarmcli -c NODE_ID -f fund_xxxx.conf
```

Establishing channel need some blocks.
You can check channel status with `ptarmcli --getinfo`.

#### memo

`pay_fundin.py` only support P2PKH / native P2WPKH / P2WPKH nested in BIP16 P2SH.  
If using "regtest", you send to `bitcoin-cli getnewaddress`.

```bash
bitcoin-cli sendtoaddress `bitcoin-cli getnewaddress` 0.1
```

### request payment

* "request payment" means:
  * create invoice
  * invoice time limit is 60 minutes
  * unit is `msat` (1/1000 satoshi)

```bash
# request 1000msat
../ptarmcli --createinvoice 1000
(print BOLT11 invoice)
```

### send payment

* pay according to BOLT11 invoice
  * You get an invoice from payee.
* You pay requested amount and payment forwarding fee each node.
* Sometime retry payment with a single `sendpayment` command.

```bash
../ptarmcli --sendpayment [BOLT11 INVOICE]
(print PAYMENT_ID)
```

* You can check the payment result using `ptarmcli --listpayment`.

```bash
# all payment list
../ptarmcli --listpayment

# specify PAYMENT_ID
../ptarmcli --listpayment=PAYMENT_ID
```

### close channel

Closing a channel uses `ptarmcli -x` command.
Amount in channel will pay to bitcoind after some blocks.

```bash
../ptarmcli -c NODE_ID -x
```

* You can check the closing status using `ptarmcli --getinfo`.
* If the "closing_wait" state continues for a long time, you can force close by `ptarmcli -xforce`.
  * Force closing need many blocks to paying from channel.
  * If the amount is too small to pay, `ptarmd` will keep it.
    * `ptarmcli --paytowallet` create and send currently payable transaction.

```bash
# check payable transaction
#   if no input found or too less to use input, outputs "no input".
../ptarmcli --paytowallet

# from internal wallet to bitcoind
../ptarmcli --paytowallet=1
```

## troubleshooting

### startup

#### wrong conf file

```text
fail: no rpcuser or rpcpassword[xxx/.bitcoin/bitcoin.conf]
fail: wrong conf file.
```

* There is no description of `rpcuser` or `rpcpassword` in conf file.

#### can't access bitcoind

```text
fail: initialize btcrpc
```

* bitcoind not started
* bitcoind JSON-RPC disabled

#### DB file version mismatch

```text
DB checking: open...done!
DB checking: version...fail: version mismatch : X(require Y)
invalid version
fail: node init
```

* exist DB file version and `ptarmd`'s DB file version not same
  * [INSTALL/NOTE](INSTALL.md#NOTE)

### Payment

#### `ptarmcli --sendpayment` always fail

* check amount you can send.
* get channel information `ptarmcli --getinfo` and check status "normal operation".
* disconnect peer and connect with `--initroutesync` for getting route information.
