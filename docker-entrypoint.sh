#!/bin/sh

touch ./ptarmapi/.env

{
  echo PTARMD_PATH='"/bitcoin/ptarmigan/install"'
  echo PTARMD_NODE_PATH='"/bitcoin/ptarmigan/install/node"'
  echo PTARMD_RPC_PORT=`expr ${LIGHTNING_PORT} + 1`
  echo PTARMD_HOST='"0.0.0.0"'
  echo BITCOIND_RPC_PORT=${RPC_PORT}
  echo BITCOIND_HOST='"'${RPC_URL}'"'
  echo BITCOIND_USER='"'${RPC_USER}'"'
  echo BITCOIND_PASS='"'${RPC_PASSWORD}'"'
} >> ./ptarmapi/.env

cd ./install && ./new_nodedir.sh ${NODE_NAME}
cd ${NODE_NAME}
../ptarmd --network=${CHAIN} \
  --port=${LIGHTNING_PORT} \
  --bitcoinrpcport=${RPC_PORT} \
  --bitcoinrpcuser=${RPC_USER} \
  --bitcoinrpcpassword=${RPC_PASSWORD} \
  --bitcoinrpcurl=${RPC_URL} \
  --announceip=${ANNOUNCE_IP} \
  --announceip_force&

cd /ptarmigan/ptarmapi
npm run start