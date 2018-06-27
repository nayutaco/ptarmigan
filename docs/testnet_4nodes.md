# testnet 4nodes

## version

* [c-lightning](https://github.com/ElementsProject/lightning)
  * commit: 0ba687732f4f00a8dd3bbad7a3656aff142e5866
* [eclair](https://github.com/ACINQ/eclair)
  * [Eclair v0.2-beta2]((https://github.com/ACINQ/eclair/releases/tag/v0.2-beta2))
* [lnd](https://github.com/lightningnetwork/lnd)
  * commit: 12cb35a6c9b4e9ee4f4ecb4b42a81602c7abbb37
* [ptarmigan](https://github.com/nayutaco/ptarmigan)
  * tag 2018-04-11

## Getting node_id

* `c-lightning`

```bash
./cli/lightning-cli getinfo
```

* `eclair`

```bash
./eclair-cli getinfo
```

* `lnd`

```bash
lncli --no-macaroons getinfo
```

* `ptarmigan`

```bash
../ucoincli -l
```

## Creating a peer CONF file

* Creating a peer configuration file
  * `node_id` is value you get on the above and IP adress is in IPv4 format.

```bash
../create_knownpeer.sh [c-lightning node_id] [node ip address] > peer_cln.conf
../create_knownpeer.sh [eclair node_id] [node ip address] > peer_eclr.conf
../create_knownpeer.sh [lnd node_id] [node ip address] > peer_lnd.conf
```

## Connecting

```bash
../ucoincli -c peer_cln.conf
../ucoincli -c peer_eclr.conf
../ucoincli -c peer_lnd.conf
```

## Creating channels

* Creating channels from `ptarmigan` to each nodes
  * Following results are for `feerate_per_kw = 10000`.

```bash
../pay_fundin.sh 1000000 800000 300000000
../ucoincli -c peer_cln.conf -f fund_yyyymmddhhddss.conf
../ucoincli -l
(wait... status: "wait_minimum_depth")
rm fund_yyyymmddhhddss.conf

../pay_fundin.sh 1000000 800000 400000000
../ucoincli -c peer_eclr.conf -f fund_yyyymmddhhddss.conf
../ucoincli -l
(wait... status: "wait_minimum_depth")
rm fund_yyyymmddhhddss.conf

../pay_fundin.sh 1000000 800000 500000000
../ucoincli -c peer_lnd.conf -f fund_yyyymmddhhddss.conf
../ucoincli -l
(wait... status: "wait_minimum_depth")
rm fund_yyyymmddhhddss.conf
```

## Waiting for opening channels

* Waiting 3 nodes change into `"established"` by observing with watch command every 10 seconds.

```bash
watch -n 10 "../ucoincli -l | jq .result.peers[].status"
```

```text
                         +--------+
                         | eclair |
                         +---+----+
                             |400000000
                             |
                             |
                             |400000000
+-------------+        +-----+-----+          +-----+
| c-lightning +--------+ ptarmigan +----------+ lnd |
+-------------+        +-----------+          +-----+
      300000000    500000000   300000000      500000000
```

## Waiting for channel announce

* Waiting for gathering 6 `channel_update`s(total 12messages) by observing with watch command

```bash
watch -n 30 "../showdb -c | jq .channel_announcement_list[].type | grep -c channel_update"
```

## Sending payment (`ecliar`-->`c-lightning`)

* `c-lightning` : Generating an invoice
  * 10000000msat == 10000000satoshi

```bash
./cli/lightning-cli invoice 10000000 xxx1 yyy1
```

```bash
./eclair-cli send <BOLT11 invoice>
```

```text
                         +--------+
                         | eclair |
                         +---+----+
                             |389998990
                             |
                             |
                             |410001010
+-------------+        +-----+-----+          +-----+
| c-lightning +--------+ ptarmigan +----------+ lnd |
+-------------+        +-----------+          +-----+
      310000000    490000000   300000000      500000000
```

## Sending payment (`lnd`-->`c-lightning`)

* `c-lightning` : Generating an invoice
  * 10000000msat == 10000000satoshi

```bash
./cli/lightning-cli invoice 10000000 xxx2 yyy2
```

```bash
lncli --no-macaroons payinvoice <BOLT11 invoice>
```

```text
                         +--------+
                         | eclair |
                         +---+----+
                             |389998990
                             |
                             |
                             |410001010
+-------------+        +-----+-----+          +-----+
| c-lightning +--------+ ptarmigan +----------+ lnd |
+-------------+        +-----------+          +-----+
      320000000    480000000   310001010      489998990
```

## Sending payment (`lnd`-->`eclair`)

* `eclair` : Generating an invoice
  * 10000000msat == 10000satoshi

```bash
./eclair-cli receive 10000000 xxx1
```

```bash
lncli --no-macaroons payinvoice <BOLT11 invoice>
```

```text
                         +--------+
                         | eclair |
                         +---+----+
                             |399998990
                             |
                             |
                             |400001010
+-------------+        +-----+-----+          +-----+
| c-lightning +--------+ ptarmigan +----------+ lnd |
+-------------+        +-----------+          +-----+
      320000000    480000000   320002020      479997980
```

## Sending payment (`c-lightning`-->`eclair`)

* `eclair` : Generating an invoice
  * 10000000msat == 10000satoshi

```bash
./eclair-cli receive 10000000 xxx2
```

```bash
./cli/lightning-cli pay <BOLT11 invoice>
```

* Supporting [automatic overpay](https://github.com/ElementsProject/lightning/pull/1257), c-lightning sends a small sum by randomly adding amount.

```text
                         +--------+
                         | eclair |
                         +---+----+
                             |410015970
                             |
                             |
                             |389984030
+-------------+        +-----+-----+          +-----+
| c-lightning +--------+ ptarmigan +----------+ lnd |
+-------------+        +-----------+          +-----+
      309982009    490017991   320002020      479997980
```

## Sending payment (`c-lightning`-->`lnd`)

* `lnd` : Generating an invoice
  * 10000satoshi

```bash
lncli --no-macaroons addinvoice --amt 10000
```

```bash
./cli/lightning-cli pay <BOLT11 invoice>
```

* Supporting [automatic overpay](https://github.com/ElementsProject/lightning/pull/1257), c-lightning sends a small sum by randomly adding amount.

```text
                         +--------+
                         | eclair |
                         +---+----+
                             |410015970
                             |
                             |
                             |389984030
+-------------+        +-----+-----+          +-----+
| c-lightning +--------+ ptarmigan +----------+ lnd |
+-------------+        +-----------+          +-----+
      299968963    500031037   309989985      490010015
```

## Sending payment (`eclair`-->`lnd`)

* `lnd` : Generating an invoice
  * 10000satoshi

```bash
lncli --no-macaroons addinvoice --amt 10000
```

```bash
./eclair-cli send <BOLT11 invoice>
```

```text
                         +--------+
                         | eclair |
                         +---+----+
                             |400014960
                             |
                             |
                             |399985040
+-------------+        +-----+-----+          +-----+
| c-lightning +--------+ ptarmigan +----------+ lnd |
+-------------+        +-----------+          +-----+
      299968963    500031037   299989985      500010015
```

## Closing channels

```bash
../ucoincli -c peer_lnd.conf -x
../ucoincli -c peer_eclr.conf -x
../ucoincli -c peer_cln.conf -x
```
