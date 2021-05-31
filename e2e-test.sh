#!/bin/bash -e

for f in test/captures/*.pcap
do
    FILE=test/captures/$(basename -s.pcap "$f")
    echo Testing $f
    TZ= ./pcap2mysql-log $f > $FILE.actual
    if [ ! -f $FILE.expected ]
    then
        cp $FILE.actual $FILE.expected
    fi
    diff $FILE.expected $FILE.actual || (echo $f && exit 1)
done
