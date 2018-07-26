# How to use

## Setup

* start bitcoind

sample: ~/.bitcoin/bitcoin.conf

```.text
testnet=1
server=1
txindex=1
rpcuser=bitcoinuser
rpcpassword=bitcoinpassword
```

## Start ptarmigan node

```.bash
cd install
./new_nodedir.sh
cd node
../ptarmd
```

## Access ptarmigan node from client app

### Get Information

```.bash
../ptarmcli -l
```

### Connect another LN node

```.bash
../ptarmcli -c [NODE_ID]@[IPv4_ADDR]:[PORT]
```

### Establish chennel

```.bash
(connect target before establish)

../pay_fundin.sh [FUND+alpha satoshi] [FUND satoshi] [to peer satoshi]
../ptarmcli -c [NODE_ID](@[IPv4_ADDR]:[PORT]) -f fundYYYYMMDDhhmmss.conf
(wait establish...)
```

### Create invoice

```.bash
../ptarmcli -i [AMOUNT_MSAT]
```

### Payment

```.bash
../ptarmcli -r [INVOICE STRING]
```

### Catch event

When event happen, `script/*.sh` is called from `ptarmd`.  
You can edit script files.
