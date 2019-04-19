#!/bin/bash
# bash ptarmiganForAzureCommandToExecute.sh "azureuser" "1" "18333" "18332" "9735" "false" ""
echo "step01 bash ptarmiganForAzureCommandToExecute.sh execute... ${1} ${2} ${3} ${4} ${5} ${6} ${7}"

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

echo "step02 create configfile"

# bitcoind
if [ ${BITCOIN_ENVIRONMENT} = "mainnet" ]; then
  # mainnet
  BITCOIN_ENVIRONMENT_SETTING="# mainnet"
  BITCOIN_PORT_SETTING=""
elif [ ${BITCOIN_ENVIRONMENT} = "testnet" ]; then
  # testnet
  BITCOIN_ENVIRONMENT_SETTING="testnet=3 # testnet"
  BITCOIN_PORT_SETTING="[testnet]\nport=${BITCOIN_PROTOCOL_PORT}\nrpcport=${BITCOIN_RPC_PORT}"
elif [ ${BITCOIN_ENVIRONMENT} = "regtest" ]; then
  # regtest
  BITCOIN_ENVIRONMENT_SETTING="regtest=1 # regtest"
  BITCOIN_PORT_SETTING="[regtest]\nport=${BITCOIN_PROTOCOL_PORT}\nrpcport=${BITCOIN_RPC_PORT}"
fi

mkdir -p $BITCOIN_CONF_PATH
cat << EOF > ${BITCOIN_CONF_PATH}/bitcoin.conf
${BITCOIN_ENVIRONMENT_SETTING}
rpcuser=bitcoinuser
rpcpassword=bitcoinpassword
rpcallowip=127.0.0.1
listen=1
server=1
daemon=1
txindex=1
`echo -e ${BITCOIN_PORT_SETTING}`
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

echo "step03 bitcoin install"
mkdir -p ${BITCOIN_PATH}
cd ${BITCOIN_PATH}
wget https://bitcoincore.org/bin/bitcoin-core-0.17.1/bitcoin-0.17.1-x86_64-linux-gnu.tar.gz
tar zxvf bitcoin-0.17.1-x86_64-linux-gnu.tar.gz
sudo cp bitcoin-0.17.1/bin/* /usr/local/bin

echo "step05 bitcoin service start"
# bitcoind start
systemctl daemon-reload
sleep 3
systemctl start bitcoin.service
systemctl enable bitcoin.service >/dev/null 2>&1

# bitcoind start and stop
# systemctl start bitcoin.service
# systemctl stop bitcoin.service

echo "step04 ptarmigan install"
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

echo "step05 start ptarmd"
mkdir ${ADMIN_USER_NAME}:${ADMIN_USER_NAME} ${PTARMIGAN_PATH}/install/node
chown -R ${ADMIN_USER_NAME}:${ADMIN_USER_NAME} ${PTARMIGAN_PATH}/install/node
cd ${ADMIN_USER_NAME}:${ADMIN_USER_NAME} ${PTARMIGAN_PATH}/install/node

# ptarmigan
if [ ${BITCOIN_ENVIRONMENT} = "mainnet" ]; then
  # mainnet
  nohup ../ptarmd --network mainnet --alias ${PTARMIGAN_NODE_ALIAS_NAME} >> ptarmd.log &
elif [ ${BITCOIN_ENVIRONMENT} = "testnet" ]; then
  # testnet
  nohup ../ptarmd --network testnet --alias ${PTARMIGAN_NODE_ALIAS_NAME} >> ptarmd.log &
elif [ ${BITCOIN_ENVIRONMENT} = "regtest" ]; then
  # regtest
  nohup ../ptarmd --network regtest --alias ${PTARMIGAN_NODE_ALIAS_NAME} >> ptarmd.log &
fi

echo "step06 install ptarmigan rest-api"
cd ${WORK_PATH}
git clone -b feature/rest-api https://github.com/nayutaco/ptarmigan.git ptarmigan-rest-api
chown -R ${ADMIN_USER_NAME}:${ADMIN_USER_NAME} ${WORK_PATH}/ptarmigan-rest-api
cd ${WORK_PATH}/ptarmigan-rest-api/ptarmapi
sudo apt install -y npm
npm install
nohup npm run start >> ptarmapi.log &

echo "step07 install complete"
