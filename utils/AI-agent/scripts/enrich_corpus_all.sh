#!/bin/bash
BASE_DIR=`dirname $0`
AFLNET=`realpath ${BASE_DIR}`/../../..

# protocols=FTP,RTSP,SMTP,SIP
protocols=FTP,RTSP,SMTP,SIP,DICOM,DNS,DTLS,SSH,TLS
for apro in $(echo $protocols | sed "s/,/ /g")
do
    for aproj in $(ls ${AFLNET}/profuzzbench/subjects/$apro)
    do
        rm -rf ${AFLNET}/profuzzbench/subjects/${apro}/${aproj}/enriched-corpus
        python3 ${AFLNET}/utils/AI-agent/corpus-enrich/enrich_corpus.py ${AFLNET}/profuzzbench/subjects/$apro/$aproj/in-${apro,,} ${AFLNET}/profuzzbench/subjects/$apro/$aproj/enriched-corpus $apro --grammar ${AFLNET}/profuzzbench/grammars/$apro --statevars ${AFLNET}/profuzzbench/subjects/$apro/$aproj/statevar.json --root ${AFLNET}/profuzzbench/subjects/$apro/$aproj
    done
    
done
