# eclair testnet

## version

* [eclair](https://github.com/ACINQ/eclair)
  * [Eclair v0.2-alpha10]((https://github.com/ACINQ/eclair/releases/download/v0.2-alpha10/eclair-node-0.2-alpha10-0beca13.jar))
* [ptarmigan](https://github.com/nayutaco/ptarmigan)
  * tag 2018-03-13
  * When ptarmigan version up with DB change is done, you need DB clean(`rm -rf dbucoin`).

----

## Set up nodes in separate computers

* First, IP adresses are `xx.xx.xx.xx` and `yy.yy.yy.yy` respectively for `eclair` and `ptarmigan`.

### Steps

#### Let's create a channel

1. Running bitcoin node

* [bitcoind] `~/.bitcoin/bitcoin.conf`

```text
rpcuser=bitcoinuser
rpcpassword=bitcoinpassword
server=1
txindex=1
testnet=1
```

* [eclair] `~/.eclair/eclair.conf`

```text
eclair.bitcoind.rpcuser=bitcoinuser
eclair.bitcoind.rpcpassword=bitcoinpassword
eclair.api.enabled=true
eclair.api.password=xxxxx
```

2. Running `bitcoind`

* eclair + bitcoind v0.16

```bash
bitcoind -deprecatedrpc=addwitnessaddress -daemon
```

* eclair + bitcoind v0.15

```bash
bitcoind -daemon
```

* ptarmigan

```bash
bitcoind -daemon
```

3. Waiting for synchronization

4. [ptarmigan] Running `ucoind`

```bash
cd install
mkdir node
cd node
../ucoind
```

5. [eclair] Running `eclair`

* Remove old DB.

```bash
rm ~/.eclair/eclair.log  ~/.eclair/eclair.sqlite  ~/.eclair/network.sqlite
```

* Running `eclair`

```bash
java -jar eclair-node-0.2-alpha10-0beca13.jar
```

* Downloading a client app
  * Edit `eclair-cli` downloaded. Fill the same words as `eclair.api.password` on `eclair.conf` in `PASSWORD` in the 8th line of text editor.
  * If not, you will be asked it every time.

```bash
wget https://raw.githubusercontent.com/ACINQ/eclair/master/eclair-core/eclair-cli
chmod u+x eclair-cli
```

6. [eclair] Getting node_id

```bash
./eclair-cli getinfo
```

7. [ptarmigan] Creating a CONF file to connect

```bash
cd install/node
../create_knownpeer.sh [eclair node_id] xx.xx.xx.xx > peer_eclr.conf
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

* If you get an error that feerate_per_kw is wrong, change fund_yyyymmddhhmmss.conf.
  * Add `feerate_per_kw=zzzzz`(zzzzz is an approximate value to an error message `localFeeratePerKw`) in the last line.

```bash
../ucoincli -c peer_eclr.conf
../ucoincli -c peer_eclr.conf -f fund_yyyymmddhhmmss.conf
```

10. [btc] Waiting for generating a block

The channel is gererated after reaching two blocks.  

When status is established in a result of -l, we can confirm that if the channel is generated.  
Combining `watch` and `jq` is also available for observing it.

```bash
watch -n 10 "../ucoincli -l | jq '.result.client[].status'"
```

Now, we will move on how to send payment.

#### `ptarmigan` --> `eclair`

1. [eclair] Generating an invoice

```bash
./eclair-cli receive 100000000 abc
```

* A unit is msatoshi.
  * `100000000 msat` = `1 mBTC`
  * You don't need to be concerned about "`abc`".

2. [ptarmigan] Sending payment

```bash
../ucoincli -r <BOLT11 invoice>
```

3. [ptarmigan] Confirming the amount after running it

```bash
../showdb w | jq
```

* If successful, our_msat will be 700000000 and their_masat will be 100000000.

#### `eclair` --> `ptarmigan`

1. [ptarmigan] Cenerating an invoice

```bash
../ucoincli -i 20000
```

* A unit is msatoshi.
  * `20000 msat` = `20 satoshi`

2. [eclair] Sending payment

```bash
./eclair-cli send <BOLT11 invoice>
```

3. [eclair] Confirming the amount after running it

```bash
./eclair-cli channels
(getting channelId)

./eclair-cli channel <channelId>
```

* If successful, `balanceMsat` will be 99980000.
