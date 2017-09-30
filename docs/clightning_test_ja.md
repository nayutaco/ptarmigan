c-lightning test
====

 1. [btc]~/bitcoin.conf
 ```
     rpcuser=bitcoinuser
     rpcpassword=bitcoinpassword
     server=1
     txindex=1
     rpcport=18443
     regtest=1
 ```
 
 2. [btc]bitcoind起動
 3. [btc] (初めてのregtestの場合)  
 ```
     $ bitcoin-cli generate 432
 ```
 4. [ptarm node]ucoind起動
 ```
     $ cd install
     $ mkdir node
     $ ./create_nodeconf.sh 8888 > node/node.conf
     $ cd node
     $ ../ucoind node.conf
 ```
 5. [cln]c-lightning起動 ([commit e418f2a7fe5c2751706fd8ac37aa50a86656b4c2](https://github.com/ElementsProject/lightning/commit/e418f2a7fe5c2751706fd8ac37aa50a86656b4c2))
 ```
     $ cd "to/clightning/dir"
     $ ./lightningd/lightningd --network=regtest --log-level=debug
 ```
 6. [cln]c-lightning node_id取得
 ```
    $ ./cli/lightning-cli getinfo
 ```
7. [ptarm]接続先CONFファイル作成
```
    $ cd install
    $ ./create_knownpeer.sh 9735 [c-lightning node_id] > peer.conf
```
8. [ptarm]fund-in transaction作成
```
    $ ./fund-in2.sh 0.01 fund.txt > node/fund.conf
```
9. [ptarm]Establish開始
```
    $ ./ucoincli -c peer.conf -f node/fund.conf 8889
```
10. [btc]block生成1(bug:修正により不要となる)
```
    $ bitcoin-cli generate 1
    (10秒ほど待つ)
```
11. [btc]block生成2
```
    $ bitcoin-cli generate 6
    (channel_announcementが展開されるまで30秒ほど待つ)
```
12. [cln]invoice作成
```
    $ ./cli/lightning-cli invoice 10000 abc
```
13. [ptarm]送金ルート準備
```
    $ ./routing regtest node/dbucoin node/node.conf [c-lightning node_id] 10000 > node/pay.conf
```
14. [ptarm]送金ルート設定ファイルにinvoiceの `rhash` を追加.  
１行目に「 `hash=[c-lightning rhash]` 」を追加
```
    $ vi node/pay.conf (viでなくてもよい)
```
15. [ptarm]現在のamountを確認
```
    $ ./showdb regtest w node/dbucoin
```
16. [ptarm]送金
```
    $ ./ucoincli -p node/pay.conf 8889
```
17. [ptarm]実施後のamountを確認
```
    $ ./showdb regtest w node/dbucoin
```
18. [ptarm]ptarmigan node_id取得
```
    $ ./ucoincli -l 8889
```
19. [ptarm]invoice作成
```
    $ ./ucoincli -i 20000 8889
```
20. [cln]送金ルート準備
```
    $ route=$(cli/lightning-cli getroute [ptarmigan node_id] 20000 1 | jq --raw-output .route -)
    $ echo $route
```
21. [cln]現在のamountを確認
```
    $ ./cli/lightning-cli getpeers
```
22. [cln]送金
```
    $ ./cli/lightning-cli sendpay "$route" [ptarmigan hash]
```
23. [cln]実施後のamountを確認
```
    $ ./cli/lightning-cli getpeers
```
