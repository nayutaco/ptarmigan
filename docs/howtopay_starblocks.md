# How to Pay starblocks/Y'alls (or Your Lightning Node) from ptarmigan Node

## 2018/03/13

- In order to make payment to destination node, the path of channels must exist.
  The "visible" node on testnet is displayed in [Lightning Network Explorer(TESTNET)](https://explorer.acinq.co/#/)
  As to connect the channels of the Lightning Network, the id, IP address, and port number of node with in this site are required(some nodes don't disclose IP address, and some nodes is not operating).
- Because Lightning Network makes payments on the P2P network, it is necessary for all node on payment path to operate correctly. Even if only one node on payment path returns an error, payment will not be completed.
- Node software is `ucoind`. Use `ucoincli` to operate `ucoind`.
- It is necessary that `bitcoind` completely synchroninzed with testnet is running on the same local host on which `ucoind` is running. It is necessary to have testnet bitcoin.
- Current user interface of `ucoincli` is not easy understandable. It is improving.
  Specify command option by mixture of file and commandline.
  i.e. "run option file generation program -> use ucoincli with commandline option and that file"
- Currently, the number of simultaneous connections is limited to a total of 20 (10 connections from the peer node, 10 connections from yourself).
- JSON-RPC port number is the specified Lightning Network protocol port number + 1.
- When executed according to the following procedure, `ptarmigan / install / node` is the directory where the node information is stored and `ptarmigan / install / node / dbucoin` is the database directory.
  Even if you exit `ucoind` software, re-running `ucoind` in the `ptarmigan / install / node` directory will start up as the same Lightning Network node.
  If re-startup is not successful, remove the `dbucoin` directory and run it as a new node (if you do not change the `node.conf` file, the node ID will not be changed).
- When version up with DB change is done, you need DB clean(`rm -rf dbucoin`).

## Overview of Payment for Starblocks/Y'alls

- Start Ubuntu16
- Install `bitcoind`
- Start `bitcoind`with testnet. Get some bitcoin from testnet faucet
- Install ptarmigan
- Start `ucoind`
- Connect `ucoind` with other testnet Lightning Network node
- Create payment channel from ptarmigan to connected node
- Issue invoice from starblocks/Y'alls WEB
- Make payment from ptarmigan with invoice
- After successful payment, WEB screen change

## Concrete operational method

1. Install `bitcoind`  Prepare`bitcoin.conf` file

```bash
sudo add-apt-repository ppa:bitcoin/bitcoin
sudo apt-get update
sudo apt-get install bitcoind
```

`~/.bitcoin/bitcoin.conf`

```text
rpcuser=bitcoinuser
rpcpassword=bitcoinpassword
server=1
txindex=1
testnet=1
```

`rpcuser` and `rpcpassword` must be specified.

2. Execute `bitcoind`

```bash
bitcoid -daemon
```

3. Wait untill fully synchronized with bitcoin testnet blockchain (it may take a few hours)

4. Generate bitcoin address by `bitcoind`. Get testnet bitcoin from bitcoin faucet WEB

```bash
bitcoin-cli getnewaddress
```

Example of faucet WEB

- https://testnet.manu.backend.hamburg/faucet
- https://tpfaucet.appspot.com/

5. Install `ptarmigan`

```bash
sudo apt install -y git autoconf pkg-config libcurl4-openssl-dev libjansson-dev libev-dev libboost-all-dev build-essential libtool jq bc
git clone https://github.com/nayutaco/ptarmigan.git
cd ptarmigan
git checkout -b test refs/tags/2018-03-03
make full
```

6. Start node daemon `ucoind`

```bash
cd install
mkdir node
cd node
../ucoind
```

Default mode is private node in which mode node does not announce IP address.  
Open another Ubuntu window and control `ucoind` from such window, because `ucoind` is daemon.

7. Generate peer node config file for `ucoind`

```bash
cd ptarmigan/install/node
../create_knownpeer.sh [Lightning node_id] [Lightning node IP address] [Lightning node port] > peer_xxx.conf
```

When `Lightning node port` is 9735, it can be ommited.

8. Connect other lightning network node from `ucoind`

```bash
../ucoincli -c peer_xxx.conf
```

When ucoind successfully connect other node, you receive the large amount of node information from peer node.  
You should wait untill finishing log output.

9. Confirm connection between  `ucoind` and peer

```bash
../ucoincli -l | jq
```

`ucoincli` shows current connection information.  
Connected node `status` is `"connected"` in the log.  
Go back 7 when connection is failed.

10. Generate funding transactionn related command file

First, send testnet bitcoin to segwit address, then send testnet bitcoinn payment channnel.

```bash
../pay_fundin.sh 1000000 800000 400000
```

These command generate a file `fund_yyyymmddhhmmss.conf`.  
File contents means the following:

  1. create 10mBTC segwit transaction
  2. send the transaction
  3. fund channel 8mBTC (give 4mBTC for peer node)

Note that unit is satoshi.

11. Fund payment channel

```bash
../ucoincli -c peer.conf -f fund_yyyymmddhhmmss.conf
```

12. Wait until funding transaction get into bitcoin testnet block (it will take time)

```bash
../ucoincli -l | jq
```

Number of comfirmation is depend on peer node(`c-lightning` default value is 1. `lnd` default value is 3).  
Display node status.  
When channel is established, status change from `"wait_minimum_depth"` to `"established"`.  
You should wait 6 confirmation, because broadcasting of channel start after 6 confirmation.  
You can check current number of confirmationn by command `ucoincli -l`.

13. Generate invoice on Starblocks/Y'alls Web

The following are famous Lightning Network(testnet) payment DEMO WEB site.

- [starblocks](https://starblocks.acinq.co/#/)
- [Y'alls](https://yalls.org/)

Here, we explain how to pay starblocks.  
Push "Add to Cart" button, and push checkout button.  
Then, invoice number is displayed.  
Long strings like `lntb********************.....` is invoice number.

14. Execute payment from ptarmigan

```bash
../ucoincli -l | jq
```

Display the node status. Comfirm the number of payment channel confirmation is more than 6.  
(When the number is less than 6, you must wait.)  

```bash
../ucoincli -r [invoice number]
```

Execute payment from ptarmigan.  
When payment starts, ptarmigan show message "Progressing".  
If payment for starblocks successfuly executed, starblocks WEB changes status.

Because Lightning Network is P2P payment, payment does not complete if even one node on the path doesn't correspond correctly.  
When payment is not completed, ptarmigan execute path re-serach.

- register estimated error payment channel into avoidance node DB.
- re-execute `ucoincli -r` internally until ptarmigan finish paymennt

It may take time.  
When ptarmigan is retrying payment, `ucoincli -l` shows "paying" message.  

When ptarmigan can not find route finally, it output "fail routing" error message.  
This mean that ptarmigan can not find route from current local channel network view.
