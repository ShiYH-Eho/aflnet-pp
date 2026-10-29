#!/bin/bash
BASE_DIR=`dirname $0`
AFLNET=`realpath ${BASE_DIR}`/../../..

# protocols=FTP,RTSP,SMTP,SIP
protocols=DICOM,DNS,DTLS,SSH,TLS
for apro in $(echo $protocols | sed "s/,/ /g")
do
    python3 ${AFLNET}/utils/AI-agent/pro-template/gen_templates.py $apro ${AFLNET}/profuzzbench/grammars/$apro --mode binary
done