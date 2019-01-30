#!/bin/bash -ue

SCRIPT_NAME=$(basename $0)
SCRIPT_DIR=$(cd $(dirname $0); pwd)
PRJ_HOME=$SCRIPT_DIR/../

(
cd $PRJ_HOME
ctags -R utl btc ln ptarmd ptarmcli showdb routing
cd -
)
