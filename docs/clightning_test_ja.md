# c-lightning test

 1. [btc]~/bitcoin.conf

```text
     rpcuser=bitcoinuser
     rpcpassword=bitcoinpassword
     server=1
     txindex=1
     rpcport=18443
     regtest=1
```

1. [btc]bitcoind起動

1. [btc] (初めてのregtestの場合)  

```bash
bitcoin-cli generate 432
```

1. [ptarm node]ucoind起動

```bash
cd install
mkdir node
./create_nodeconf.sh 8888 > node/node.conf
cd node
../ucoind node.conf
```

1. [cln]c-lightning起動 ([commit e418f2a7fe5c2751706fd8ac37aa50a86656b4c2](https://github.com/ElementsProject/lightning/commit/e418f2a7fe5c2751706fd8ac37aa50a86656b4c2))

```bash
cd "to/clightning/dir"
./lightningd/lightningd --network=regtest --log-level=debug
```

1. [cln]c-lightning node_id取得

```bash
./cli/lightning-cli getinfo
```

1. [ptarm]接続先CONFファイル作成

```bash
cd install
./create_knownpeer.sh 9735 [c-lightning node_id] > peer.conf
```

1. [ptarm]fund-in transaction作成

```bash
./fund-in2.sh 0.01 fund.txt > node/fund.conf
```

1. [ptarm]Establish開始

```bash
./ucoincli -c peer.conf -f node/fund.conf 8889
```

1. [btc]block生成1(bug:修正により不要となる)

```bash
bitcoin-cli generate 1
    (10秒ほど待つ)
```

1. [btc]block生成2

```bash
bitcoin-cli generate 6
    (channel_announcementが展開されるまで30秒ほど待つ)
```

1. [cln]invoice作成

```bash
./cli/lightning-cli invoice 10000 abc
```

1. [ptarm]送金ルート準備

```bash
./routing regtest node/dbucoin `./ucoind node/node.conf id` [c-lightning node_id] 10000 > node/pay.conf
```

1. [ptarm]送金ルート設定ファイルにinvoiceの `rhash` を追加.  

１行目に「 `hash=[c-lightning rhash]` 」を追加

```bash
vi node/pay.conf (viでなくてもよい)
```

1. [ptarm]現在のamountを確認

```bash
./showdb regtest w node/dbucoin
```

1. [ptarm]送金

```bash
./ucoincli -p node/pay.conf 8889
```

1. [ptarm]実施後のamountを確認

```bash
./showdb regtest w node/dbucoin
```

1. [ptarm]ptarmigan node_id取得

```bash
./ucoincli -l 8889
```

1. [ptarm]invoice作成

```bash
./ucoincli -i 20000 8889
```

1. [cln]送金ルート準備

```bash
route=$(cli/lightning-cli getroute [ptarmigan node_id] 20000 1 | jq --raw-output .route -)
echo $route
```

1. [cln]現在のamountを確認

```bash
./cli/lightning-cli getpeers
```

1. [cln]送金

```bash
./cli/lightning-cli sendpay "$route" [ptarmigan hash]
```

1. [cln]実施後のamountを確認

```bash
./cli/lightning-cli getpeers
```
