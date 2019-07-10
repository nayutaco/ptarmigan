#!/bin/bash
set -eu

#   method: htlc_changed
#   $1: short_channel_id
#   $2: node_id
#   $3: local_msat
DATE=`date -u +"%Y-%m-%dT%H:%M:%S.%N"`
cat << EOS | jq -e '.'
{
    "method":"htlc_changed",
    "date":"$DATE",
    "short_channel_id":"$1",
    "node_id":"$2",
    "local_msat":$3
}
EOS

if [ "${API_TOKEN:-unknown}" == unknown ]; then
  API_TOKEN=ptarmigan
fi

curl=`cat <<EOS
curl
 -s -o
 --request POST
 http://0.0.0.0:3000/notification/htlcchanged
 --header 'Content-Type: application/json'
 --header "Authorization: Bearer $API_TOKEN"
EOS`
eval ${curl}