# How to Pay starblocks (or Your Lightning Node) from ptarmigan Node

## 2018/09/09

- In order to make payment to destination node, the path of channels must exist.
  The "visible" node on testnet is displayed in [Lightning Network Explorer(TESTNET)](https://explorer.acinq.co/#/)
  As to connect the channels of the Lightning Network, the id, IP address, and port number of node with in this site are required(some nodes don't disclose IP address, and some nodes is not operating).
- Node software is `ptarmd`. Use `ptarmcli` to operate `ptarmd`.
- It is necessary that `bitcoind` completely synchroninzed with testnet is running on the same local host on which `ptarmd` is running. It is necessary to have testnet bitcoin.
- Current user interface of `ptarmcli` is not easy understandable. It is improving.
  Specify command option by mixture of file and commandline.
  i.e. "run option file generation program -> use ptarmcli with commandline option and that file"
- Currently, the number of simultaneous connections is limited to a total of 20 (10 connections from the peer node, 10 connections from yourself).
- JSON-RPC port number is the specified Lightning Network protocol port number + 1.
- When executed according to the following procedure, `ptarmigan / install / node` is the directory where the node information is stored and `ptarmigan / install / node / db` is the database directory.
  Even if you exit `ptarmd` software, re-running `ptarmd` in the `ptarmigan / install / node` directory will start up as the same Lightning Network node.
  If re-startup is not successful, remove the `db` directory and run it as a new node.
- When version up with DB change is done, you need DB clean(`rm -rf db`).

## Overview of Payment for Starblocks

- Start Ubuntu16
- Install `bitcoind`
- Start `bitcoind`with testnet. Get some bitcoin from testnet faucet
- Install ptarmigan
- Start `ptarmd`
- Connect `ptarmd` with other testnet Lightning Network node
- Create payment channel from ptarmigan to connected node
- Issue invoice from starblocks WEB
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

3. Wait until fully synchronized with bitcoin testnet blockchain (it may take a few hours)

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
make full
```

6. Start node daemon `ptarmd`

```bash
cd install
./new_nodedir.sh
cd node
../ptarmd --network=testnet&
```

Default mode is private node in which mode node does not announce IP address.  
Open another Ubuntu window and control `ptarmd` from such window, because `ptarmd` is daemon.

8. Connect other lightning network node from `ptarmd`

```bash
../ptarmcli -c [peer node_id]@[peer IP address]:[peer port]
```

When ptarmd successfully connect other node, you receive the large amount of node information from peer node.  
You should wait until finishing log output.

9. Confirm connection between  `ptarmd` and peer

```bash
../ptarmcli -l | jq
```

`ptarmcli` shows current connection information.  
Connected node `status` is `"connected"` in the log.  

11. Fund payment channel

fund channel 10mBTC, and give 500000msat for peer node.

```bash
../ptarmcli -c [peer node_id] -f 1000000,500000
```

12. Wait until funding transaction get into bitcoin testnet block (it will take time)

```bash
../ptarmcli -l | jq
```

Number of confirmation is depend on peer node(`c-lightning` default value is 1. `lnd` default value is 3).
Display node status.  
When channel is established, status change from `"wait_minimum_depth"` to `"established"`.  
You should wait 6 confirmation, because broadcasting of channel start after 6 confirmation.  
You can check current number of confirmationn by command `ptarmcli -l`.

13. Generate invoice on Starblocks Web

The following are famous Lightning Network(testnet) payment DEMO WEB site.

- [starblocks](https://starblocks.acinq.co/#/)

Here, we explain how to pay starblocks.  
Push "Add to Cart" button, and push checkout button.  
Then, invoice number is displayed.  
Long strings like `lntb********************.....` is invoice text.

14. Execute payment from ptarmigan

```bash
../ptarmcli -l | jq
```

Display the node status.

```bash
../ptarmcli -r [invoice text]
```

Execute payment from ptarmigan.  
When payment starts, ptarmigan show message "Progressing".  
If payment for starblocks successfully executed, starblocks WEB changes status.

Because Lightning Network is P2P payment, payment does not complete if even one node on the path doesn't correspond correctly.  
When payment is not completed, ptarmigan execute path re-serach.

- register estimated error payment channel into avoidance node DB.
- re-execute `ptarmcli -r` internally until ptarmigan finish paymennt

It may take time.  
When ptarmigan is retrying payment, `ptarmcli -l` shows "paying" message.  

When ptarmigan can not find route finally, it output "fail routing" error message.  
This mean that ptarmigan can not find route from current local channel network view.
