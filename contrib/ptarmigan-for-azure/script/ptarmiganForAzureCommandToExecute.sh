#!/bin/bash
# bash ptarmiganForAzureCommandToExecute.sh "azureuser" "1" "18333" "18332" "9735" "false" ""
echo "bash ptarmiganForAzureCommandToExecute.sh execute... ${1} ${2} ${3} ${4} ${5} ${6} ${7}"

ADMIN_USER_NAME=${1:?}
BITCOIN_ENVIRONMENT=${2:?}
BITCOIN_PROTOCOL_PORT=${3:?}
BITCOIN_RPC_PORT=${4:?}
PTARMIGAN_PORT=${5:?}
PTARMIGAN_NODE_ANNOUNCEMENT=${6:?}
PTARMIGAN_NODE_ALIAS_NAME=${7}

HOME_PATH=/home/${ADMIN_USER_NAME}
WORK_PATH=${HOME_PATH}/work
BITCOIN_PATH=${WORK_PATH}/bitcoin
PTARMIGAN_PATH=${WORK_PATH}/ptarmigan
BITCOIN_CONF_PATH=${HOME_PATH}/.bitcoin
BITCOIND_PATH=/usr/local/bin
BDB_PREFIX=${WORK_PATH}/bitcoin/db4

echo "step01 package install"

sudo apt -y update
sudo apt -y upgrade

sudo apt -y install build-essential
sudo apt -y install libtool autotools-dev automake
sudo apt -y install pkg-config bsdmainutils python3
sudo apt -y install software-properties-common
sudo apt -y install libboost-all-dev
sudo apt -y install libdb4.8-dev libdb4.8++-dev
sudo apt -y install libqrencode-dev autoconf openssl libssl-dev libevent-dev
sudo apt -y install libminiupnpc-dev
sudo apt -y install libzmq3-dev

echo "step02 create configfile"

# bitcoind
if [ ${BITCOIN_ENVIRONMENT} = "mainnet" ]; then
  # mainnet
  BITCOIN_ENVIRONMENT_SETTING="# mainnet"
elif [ ${BITCOIN_ENVIRONMENT} = "testnet" ]; then
  # testnet
  BITCOIN_ENVIRONMENT_SETTING="testnet=3 # testnet"
elif [ ${BITCOIN_ENVIRONMENT} = "regtest" ]; then
  # regtest
  BITCOIN_ENVIRONMENT_SETTING="regtest=1 # regtest"
else
  BITCOIN_ENVIRONMENT_SETTING="testnet=3 # testnet"
fi

mkdir -p $BITCOIN_CONF_PATH
cat << EOF > ${BITCOIN_CONF_PATH}/bitcoin.conf
${BITCOIN_ENVIRONMENT_SETTING}
port=${BITCOIN_PROTOCOL_PORT}
rpcuser=bitcoinuser
rpcpassword=bitcoinpassword
rpcport=${BITCOIN_RPC_PORT}
rpcallowip=127.0.0.1
listen=1
server=1
daemon=1
txindex=1
EOF

chown -R ${ADMIN_USER_NAME}:${ADMIN_USER_NAME} $BITCOIN_CONF_PATH

# ptarmigan

# bitcoin service
cat << EOF > /etc/systemd/system/bitcoin.service
[Unit]
Description=Bitcoin service
After=network.target

[Service]
ExecStart=$BITCOIND_PATH/bitcoind -daemon -conf=$BITCOIN_CONF_PATH/bitcoin.conf -datadir=$BITCOIN_CONF_PATH
ExecStop=-$BITCOIND_PATH/bitcoin-cli -conf=$BITCOIN_CONF_PATH/bitcoin.conf -datadir=$BITCOIN_CONF_PATH stop

User=${ADMIN_USER_NAME}
Group=${ADMIN_USER_NAME}

RuntimeDirectory=${ADMIN_USER_NAME}
RuntimeDirectoryMode=0710

ConfigurationDirectory=${ADMIN_USER_NAME}
ConfigurationDirectoryMode=0710

StateDirectory=${ADMIN_USER_NAME}
StateDirectoryMode=0710

Type=forking
#PIDFile=$BITCOIN_CONF_PATH/bitcoin.pid

Restart=always
PrivateTmp=true
TimeoutStopSec=60s
TimeoutStartSec=10s
StartLimitInterval=120s
StartLimitBurst=5

[Install]
WantedBy=multi-user.target
EOF


echo "step03 ptarmigan install"
sudo apt -y update
sudo apt -y upgrade
sudo apt install -y git autoconf pkg-config build-essential libtool wget jq bc
mkdir -p ${WORK_PATH}
chown -R ${ADMIN_USER_NAME}:${ADMIN_USER_NAME} ${WORK_PATH}

cd ${WORK_PATH}
git clone https://github.com/nayutaco/ptarmigan.git
cd ${PTARMIGAN_PATH}
make full

chown -R ${ADMIN_USER_NAME}:${ADMIN_USER_NAME} ${PTARMIGAN_PATH}

echo "step04 bitcoin install"
mkdir -p ${WORK_PATH}

cd ${WORK_PATH}
git clone https://github.com/bitcoin/bitcoin.git
cd ${BITCOIN_PATH}
./contrib/install_db4.sh `pwd`

./autogen.sh
./configure --without-gui BDB_LIBS="-L${BDB_PREFIX}/lib -ldb_cxx-4.8" BDB_CFLAGS="-I${BDB_PREFIX}/include"
sudo make -j4
sudo make install

chown -R ${ADMIN_USER_NAME}:${ADMIN_USER_NAME} ${BITCOIN_PATH}

echo "step05 bitcoin service start"

# bitcoind start
systemctl daemon-reload
sleep 3
systemctl start bitcoin.service
systemctl enable bitcoin.service >/dev/null 2>&1

# bitcoind start and stop
# systemctl start bitcoin.service
# systemctl stop bitcoin.service

echo "step06 start ptarmign"
mkdir ${ADMIN_USER_NAME}:${ADMIN_USER_NAME} ${PTARMIGAN_PATH}/install/node
chown -R ${ADMIN_USER_NAME}:${ADMIN_USER_NAME} ${PTARMIGAN_PATH}/install/node
cd ${ADMIN_USER_NAME}:${ADMIN_USER_NAME} ${PTARMIGAN_PATH}/install/node

# bitcoind
if [ ${BITCOIN_ENVIRONMENT} = "mainnet" ]; then
  # mainnet
  ../ptarmd --network mainnet
elif [ ${BITCOIN_ENVIRONMENT} = "testnet" ]; then
  # testnet
  ../ptarmd --network testnet
  BITCOIN_ENVIRONMENT_SETTING="testnet=3 # testnet"
elif [ ${BITCOIN_ENVIRONMENT} = "regtest" ]; then
  # regtest
  ../ptarmd --network regtest

echo "step07 install ptarmigan rest-api"

echo "step08 setup complete"
