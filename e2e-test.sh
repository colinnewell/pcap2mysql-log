#!/bin/bash

for f in test/captures/*.pcap
do
    FILE=test/captures/$(basename -s.pcap "$f")
    echo Testing $f
    TZ= ./pcap2mysql-log $f > $FILE.actual
    if [ ! -f $FILE.expected ]
    then
        cp $FILE.actual $FILE.expected
    fi
    diff -q $FILE.expected $FILE.actual || (echo Failed diff $FILE.expected $FILE.actual && exit 1)
done


FILE=test/captures/compressed.raw
TZ= ./pcap2mysql-log test/captures/compressed.pcap --raw-data > $FILE.actual
if [ ! -f $FILE.expected ]
then
    cp $FILE.actual $FILE.expected
fi
diff -q $FILE.expected $FILE.actual || (echo Failed diff $FILE.expected $FILE.actual && exit 1)
