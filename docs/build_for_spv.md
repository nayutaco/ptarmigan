# Build Ptarmigan for SPV

## Easy for Raspberry Pi Zero settings

```bash
cd ptarmigan
./tools/rpi_bj.sh
# edit options.mak and install/jdk.sh for Raspbery Pi Zero
```

## Build

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

## Execute

* configure

```bash
cd install

# edit your environment(if need)
vi jdk.sh
(select your TARGET)

source jdk.sh
```

## Usage

* start node

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