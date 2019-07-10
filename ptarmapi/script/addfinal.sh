#!/bin/bash
set -eu

#   method: addfinal
#   $1: short_channel_id
#   $2: node_id
#   $3: payment_hash
#   $4: amount_msat
#   $5: local_msat
DATE=`date -u +"%Y-%m-%dT%H:%M:%S.%N"`
cat << EOS | jq -e '.'
{
    "method":"addfinal",
    "date":"$DATE",
    "short_channel_id":"$1",
    "node_id":"$2",
    "payment_hash":"$3",
    "amount_msat":$4,
    "local_msat":$5
}
EOS

json=$(cat << EOS
{"paymentHash":"$3"}
EOS
)

if [ "${API_TOKEN:-unknown}" == unknown ]; then
  API_TOKEN=ptarmigan
fi

curl=`cat <<EOS
curl
 -s -o
 --request POST
 http://0.0.0.0:3000/notification/addfinal
 --header 'Content-Type: application/json'
 --header "Authorization: Bearer $API_TOKEN"
 --data '$json'
EOS`
eval ${curl}