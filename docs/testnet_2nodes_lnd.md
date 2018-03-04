# lnd testnet

## version

* bitcoind v0.15.x(not v0.16.x)
* [lnd](https://github.com/lightningnetwork/lnd/tree/00ea46d9aeabf670dfb18c9e9c5f10f741ff5192) : commit 00ea46d9aeabf670dfb18c9e9c5f10f741ff5192
* [ptarmigan](https://github.com/nayutaco/ptarmigan/tree/2018-03-03) : tag 2018-03-03  (git checkout -b test refs/tags/2018-03-03)
  * When ptarmigan version up with DB change is done, you need DB clean(`rm -rf dbucoin`).  
    (Next version up will be include DB change)

----

## Set up nodes in separate computers

* First, IP adresses are `xx.xx.xx.xx` and `yy.yy.yy.yy` respectively for `lnd` and `ptarmigan`.

### Steps

#### Let's create a channel.

 1. Running bitcoin node

 * [bitcoind] `~/.bitcoin/bitcoin.conf`

```text
rpcuser=bitcoinuser
rpcpassword=bitcoinpassword
server=1
txindex=1
testnet=1
```

* [btcd] `~/.btcd/btcd.conf`

```text
testnet=1
txindex=1
rpcuser=nayuta
rpcpass=nayuta
```

* [btcd] `~/.btcctl/btcctl.conf`

```text
rpcuser=nayuta
rpcpass=nayuta
```

* [lnd] `~/.lnd/lnd.conf`

```text
[Application Options]
debughtlc=true
maxpendingchannels=10
no-macaroons=true
debuglevel=trace
nobootstrap=1

[Bitcoin]
bitcoin.active=1
bitcoin.testnet=1
bitcoin.node=btcd
```

2. Running `bitcoind`/`btcd`

```bash
bitcoind -daemon
```

```bash
btcd&
```

3. Waiting for synchronization

4. [ptarmigan] Running `ucoind`

```bash
cd install
mkdir node
cd node
../ucoind
```

5. [lnd] Running `lnd`

* Remove old DB

```bash
rm -rf ~/.lnd/data
```

* Running `lnd`

```bash
lnd
```

* Creating a wallet
  * All you have to do is using `lncli --no-macaroons unlock` next time.

```bash
lncli --no-macaroons create
```

6. [lnd] Getting node_id

```bash
lncli --no-macaroons getinfo
```

7. [ptarmigan] Creating a CONF file to connect

```bash
cd install/node
../create_knownpeer.sh [lnd node_id] xx.xx.xx.xx > peer_lnd.conf
```

8. [ptarmigan] Creating fund-in transaction

```bash
../pay_fundin.sh 1000000 800000 0
```

* Create a channel that sends you 8mBTC and the other person 0.
  * 1000000 (fund-in satoshi) is the amount of money that is sent to an adress before sending payment to the channel.
  * 800000 (channel satoshi) is the amount of sending payment to the channel.
  * 0 (push satoshi) is the amount out of channel satoshi to be sent to the other person.
* `pay_fundin.sh` will create a file in `fund_yyyymmddhhmmss.conf` format.

9. [ptarmigan] Starting Channel Establishment

```bash
../ucoincli -c peer_lnd.conf
../ucoincli -c peer_lnd.conf -f fund_yyyymmddhhmmss.conf
```

10. [btc] Waiting for generating a block

The channel is gererated after reaching three blocks.  

When status is established in a result of `ucoincli -l`, we can confirm that if the channel is generated.  
Combining `watch` and `jq` is also available for observing it.

```bash
watch -n 10 "../ucoincli -l | jq '.result.client[].status'"
```

Now we will move on how to send payment.

#### `ptarmigan` --> `lnd`

1. [lnd] Generating an invoice

```bash
lncli --no-macaroons addinvoice --amt 100000
```

* A unit is msatoshi.
  * `100000 satoshi` = `1 mBTC`

2. [ptarmigan] Sending payment

```bash
../ucoincli -r <BOLT11 invoice>
```

3. [ptarmigan] Confirming the amount after running it

```bash
../showdb w | jq
```

* If successful, our_msat will be 700000000 and their_masat will be 10000000.

#### `lnd` --> `ptarmigan`

1. [ptarmigan] Cenerating an invoice

```bash
../ucoincli -i 20000
```

* A unit is msatoshi.
  * `20000 msat` = `20 satoshi`

2. [lnd] Sending payment

```bash
lncli --no-macaroons payinvoice <BOLT11 invoice>
```

3. [lnd] Confirming the amount after running it

```bash
lncli --no-macaroons listchannels
```

* If successful, `local_balance` will be 99980.
