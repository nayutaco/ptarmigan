# build ptarmd for SPV

## build

* JDK
  * Raspberry Pi2/3(Cortex-A)
    * already installed (maybe)
  * Raspberry Pi1/Zero (Arm11)
    * install `openjdk-8-jdk`

```bash
sudo apt remove -y oracle-java8-jdk
sudo apt install -y openjdk-8-jdk
```

* configure

  * `options.mak`
    * set `NODE_TYPE=BITCOINJ`

* build

```bash
make clean
make
```

## execute

* configure

```bash
cd install

# edit your environment(if need)
vi jdk.sh
(uncomment your TARGET)

source jdk.sh
```

## usage

* start (testnet)

```bash
cd install
./new_nodedir.sh spv
cd spv
../ptarmd --network=testnet&
#start blockchain syncing...
#   take a long time........
```

* fund-in
  * get address for fund-in
  * you send from your wallet to the address.

```bash
# like `bitcoin-cli getnewaddress`
../ptarmcli --getnewaddress
```

* funding from fund-in amount

```bash
# check you have fund-in amount
../ptarmcli --getbalance

# funding
../ptarmcli -c xxxxxxxx....xxxx@yyy.yyy.yyy.yyy:zzzz -f FUNDING_SATOSHIS
```

* send fund-in amount to address

```bash
# send all amount to address
../ptarmcli --emptywallet YOUR_RECEIVING_ADDRESS
```