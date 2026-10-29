#!/bin/bash
BASE_DIR=`dirname $0`
AFLNET=`realpath ${BASE_DIR}`/../../..

for apro in $(ls ${AFLNET}/profuzzbench/subjects)
do
    for aproj in $(ls ${AFLNET}/profuzzbench/subjects/$apro)
    do
        python3 ${AFLNET}/utils/AI-agent/statevar/identify.py --protocol ${apro} ${AFLNET}/profuzzbench/subjects/$apro/$aproj/repo ${AFLNET}/profuzzbench/subjects/$apro/$aproj/statevar.json 
    done
done