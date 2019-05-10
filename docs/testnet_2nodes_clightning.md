# c-lightning testnet

## version

* [c-lightning](https://github.com/ElementsProject/lightning)
  * commit: 74a444eb7aa29ffca693a3ae5fed43dfdcc722e0
* [ptarmigan](https://github.com/nayutaco/ptarmigan)
  * tag: 2018-03-13
  * When ptarmigan version up with DB change is done, you need DB clean(`rm -rf db`)

----

## Set up nodes in separate computers

* First, IP adresses are `xx.xx.xx.xx` and `yy.yy.yy.yy` respectively for `c-lightning` and `ptarmigan`.

### Steps

#### Let's create a channel

 1. [btc] Edit `~/.bitcoin/bitcoin.conf`

```text
rpcuser=bitcoinuser
rpcpassword=bitcoinpassword
server=1
txindex=1
testnet=1
```

2. [btc] Running `bitcoind`

```bash
bitcoind -daemon
```

3. [btc] Waiting for synchronization

4. [ptarmigan] Running `ptarmd`

```bash
cd install
./new_nodedir.sh
cd node
../ptarmd --network=testnet&
```

5. [c-lightning] Running `c-lightning`

* Remove old DB

```bash
rm -rf ~/.lightning
```

* Running `c-lightning`

```bash
./lightningd/lightningd --network=testnet
```

6. [c-lightning] Getting node_id

```bash
./cli/lightning-cli getinfo
```

9. [ptarmigan] Starting Channel Establishment

```bash
../ptarmcli -c [PEER NODE_ID]@[IPv4 ADDR]:[PORT]
../ptarmcli -c [PEER NODE_ID] -f 1000000
```

10. [btc] Waiting for generating a block

The channel is gererated after reaching one block.  

When status is established in a result of `ptarmcli -l`, we can confirm that if the channel is generated.  
Combining `watch` and `jq` is also available for observing it.

```bash
watch -n 10 "../ptarmcli -l | jq '.result.client[].status'"
```

Now, we will move on how to send payment.

#### `ptarmigan` --> `c-lightning`

1. [c-lightning] Generating an invoice

```bash
./cli/lightning-cli invoice 100000000 abc def
```

* A unit is msatoshi.
  * `100000000 msat` = `1 mBTC`
  * You don't need to be concerned about "abc" or "def".
* We can get its result in JSON format.
  * Invoice to use this time is `"bolt11"`.

2. [ptarmigan] Sending payment

```bash
../ptarmcli -r <BOLT11 invoice>
```

3. [ptarmigan] Confirming the amount after running it

```bash
../showdb -w | jq
```

#### `c-lightning` --> `ptarmigan`

1. [ptarmigan] Cenerating an invoice

```bash
../ptarmcli -i 20000
```

* A unit is msatoshi.
  * `20000 msat` = `20 satoshi`

2. [c-lightning] Sending payment

```bash
./cli/lightning-cli pay <BOLT11 invoice>
```

3. [c-lightning] Confirming the amount after running it

```bash
./cli/lightning-cli listpeers | jq
```
