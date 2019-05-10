# testnet 4nodes

## node

* [c-lightning](https://github.com/ElementsProject/lightning)
* [eclair](https://github.com/ACINQ/eclair)
* [lnd](https://github.com/lightningnetwork/lnd)
* [ptarmigan](https://github.com/nayutaco/ptarmigan)

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
../ptarmcli -l
```

## Connecting

```bash
../ptarmcli -c [c-lightning NODE_ID]@[IPv4 ADDR]:[PORT]
../ptarmcli -c [eclair NODE_ID]@[IPv4 ADDR]:[PORT]
../ptarmcli -c [lnd NODE_ID]@[IPv4 ADDR]:[PORT]
```

## Creating channels

* Creating channels from `ptarmigan` to each nodes
  * Following results are for `feerate_per_kw = 10000`.

```bash
../ptarmcli -c [c-lightning NODE_ID] -f 800000,300000000
../ptarmcli -l
(wait... status: "wait_minimum_depth")

../ptarmcli -c [eclair NODE_ID] -f 800000,400000000
../ptarmcli -l
(wait... status: "wait_minimum_depth")

../ptarmcli -c [lnd NODE_ID] -f 800000,500000000
../ptarmcli -l
(wait... status: "wait_minimum_depth")
```

## Waiting for opening channels

* Waiting 3 nodes change into `"established"` by observing with watch command every 10 seconds.

```bash
watch -n 10 "../ptarmcli -l | jq .result.peers[].status"
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

## Sending payment (`lnd`-->`c-lightning`)

* `c-lightning` : Generating an invoice
  * 10000000msat == 10000000satoshi

```bash
./cli/lightning-cli invoice 10000000 xxx2 yyy2
```

```bash
lncli --no-macaroons payinvoice <BOLT11 invoice>
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

## Sending payment (`eclair`-->`lnd`)

* `lnd` : Generating an invoice
  * 10000satoshi

```bash
lncli --no-macaroons addinvoice --amt 10000
```

```bash
./eclair-cli send <BOLT11 invoice>
```

## Closing channels

```bash
../ptarmcli -c [lnd NODE_ID] -x
../ptarmcli -c [eclair NODE_ID] -x
../ptarmcli -c [c-lightning NODE_ID] -x
```
