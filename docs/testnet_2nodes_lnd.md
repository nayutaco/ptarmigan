# lnd testnet

## version

* [lnd](https://github.com/lightningnetwork/lnd/)
  * commit: 45eaa70814e8f94a569bc277c52a79a5c4351c43
* [ptarmigan](https://github.com/nayutaco/ptarmigan/)
  * tag: 2018-03-13
  * When ptarmigan version up with DB change is done, you need DB clean(`rm -rf db`).

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

4. [ptarmigan] Running `ptarmd`

```bash
cd install
./new_nodedir.sh
cd node
../ptarmd --network=testnet&
```

5. [lnd] Running `lnd`

* Remove old DB

```bash
rm -rf ~/.lnd/data
```

* Running `lnd`

```bash
lnd --no-macaroons
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
../ptarmcli -c [PEER NODE_ID]@[IPv4 ADDR]:[PORT]
../ptarmcli -c [PEER NODE_ID] -f fund_yyyymmddhhmmss.conf
```

10. [btc] Waiting for generating a block

The channel is gererated after reaching three blocks.  

When status is established in a result of `ptarmcli -l`, we can confirm that if the channel is generated.  
Combining `watch` and `jq` is also available for observing it.

```bash
watch -n 10 "../ptarmcli -l | jq '.result.client[].status'"
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
../ptarmcli -r <BOLT11 invoice>
```

3. [ptarmigan] Confirming the amount after running it

```bash
../showdb -w | jq
```

#### `lnd` --> `ptarmigan`

1. [ptarmigan] Cenerating an invoice

```bash
../ptarmcli -i 20000
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
