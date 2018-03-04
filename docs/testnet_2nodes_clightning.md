# c-lightning testnet

## version

* bitcoind v0.15.x(not v0.16.x)
* [c-lightning](https://github.com/ElementsProject/lightning/tree/b536e97df29e2881eda0bda008a3c8b1e412d249) : commit b536e97df29e2881eda0bda008a3c8b1e412d249
* [ptarmigan](https://github.com/nayutaco/ptarmigan/tree/2018-03-03) : tag 2018-03-03  (git checkout -b test refs/tags/2018-03-03).
  * When ptarmigan version up with DB change is done, you need DB clean(`rm -rf dbucoin`)  
    (Next version up will be include DB change)

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

4. [ptarmigan] Running `ucoind`

```bash
cd install
mkdir node
cd node
../ucoind
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

7. [ptarmigan] Creating a CONF file to connect

```bash
cd install/node
../create_knownpeer.sh [c-lightning node_id] xx.xx.xx.xx > peer_cln.conf
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
../ucoincli -c peer_cln.conf
../ucoincli -c peer_cln.conf -f fund_yyyymmddhhmmss.conf
```

10. [btc] Waiting for generating a block

The channel is gererated after reaching one block.  

When status is established in a result of `ucoincli -l`, we can confirm that if the channel is generated.  
Combining `watch` and `jq` is also available for observing it.

```bash
watch -n 10 "../ucoincli -l | jq '.result.client[].status'"
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
../ucoincli -r <BOLT11 invoice>
```

3. [ptarmigan] Confirming the amount after running it

```bash
../showdb w | jq
```

* If successful, `our_msat` will be 700000000 and `their_msat` will be 100000000.

#### `c-lightning` --> `ptarmigan`

1. [ptarmigan] Cenerating an invoice

```bash
../ucoincli -i 20000
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

* If successful, `msatoshi_to_us` will be 99980000.
