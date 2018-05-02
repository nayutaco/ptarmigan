#!/bin/bash
#   method: error
#   $1: short_channel_id
#   $2: node_id
#   $3: err_str
DATE=`date +"%Y-%m-%dT%H:%M:%S.%N"`
echo "{ \"method\": \"error\", \"short_channel_id\": \"$1\", \"node_id\": \"$2\", \"date\": \"$DATE\", \"err_str\": \"$3\" }" | jq -c .

# echo "from $2($1):" >> err_$1.log
# echo "$3" >> err_$1.log
# echo "" >> err_$1.log
