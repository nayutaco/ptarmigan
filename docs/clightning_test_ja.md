# c-lightning test

 1. [btc]~/.bitcoin/bitcoin.conf

```text
rpcuser=bitcoinuser
rpcpassword=bitcoinpassword
server=1
txindex=1
rpcport=18443
regtest=1
```

2. [btc]bitcoind起動

3. [btc] (初めてのregtestの場合)  

```bash
bitcoin-cli generate 432
```

4. [ptarm node]ucoind起動

```bash
cd install
mkdir node
./create_testnodeconf.sh 8888 > node/node.conf
cd node
../ucoind node.conf
```

5. [cln]c-lightning起動 ([commit ebdecebb1a89f7dcd8daa53c57ec58af32f7c40d](https://github.com/ElementsProject/lightning/tree/ebdecebb1a89f7dcd8daa53c57ec58af32f7c40d))

```bash
cd "to/clightning/dir"
./lightningd/lightningd --network=regtest --log-level=debug
```

6. [cln]c-lightning node_id取得

```bash
./cli/lightning-cli getinfo
```

7. [ptarm]接続先CONFファイル作成

```bash
cd install
./create_knownpeer.sh [c-lightning node_id] 127.0.0.1 > peer.conf
```

8. [ptarm]fund-in transaction作成

```bash
./fund-in.sh 0.01 fund.txt > node/fund.conf
```

9. [ptarm]Establish開始

```bash
./ucoincli -c peer.conf 8889
./ucoincli -c peer.conf -f node/fund.conf 8889
```

10. [btc]block生成

```bash
bitcoin-cli generate 6
    (channel_announcementが展開されるまで30秒ほど待つ)
```

11. [cln]invoice作成(rhash取得)

```bash
./cli/lightning-cli invoice 10000 abc
```

12. [ptarm]送金ルート準備

```bash
./routing regtest node/dbucoin `./ucoind node/node.conf id` [c-lightning node_id] 10000 > node/pay.conf
```

13. [ptarm]現在のamountを確認

```bash
./showdb regtest w node/dbucoin
```

14. [ptarm]送金

```bash
./ucoincli -p node/pay.conf,[c-lightning rhash] 8889
```

15. [ptarm]実施後のamountを確認

```bash
./showdb regtest w node/dbucoin
```

16. [ptarm]ptarmigan node_id取得

```bash
./ucoincli -l 8889
```

17. [ptarm]invoice作成

```bash
./ucoincli -i 20000 8889
```

18. [cln]送金ルート準備

```bash
route=$(cli/lightning-cli getroute [ptarmigan node_id] 20000 1 | jq --raw-output .route -)
echo $route
```

19. [cln]現在のamountを確認

```bash
./cli/lightning-cli getpeers
```

20. [cln]送金

```bash
./cli/lightning-cli sendpay "$route" [ptarmigan hash]
```

21. [cln]実施後のamountを確認

```bash
./cli/lightning-cli getpeers
```
