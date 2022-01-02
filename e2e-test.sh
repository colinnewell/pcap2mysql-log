#!/bin/bash

for f in test/captures/*.pcap
do
    FILE=test/captures/$(basename -s.pcap "$f")
    echo Testing $f
    if [[ "$f" == "test/captures/numeric-types.pcap" ]]
    then
        # avoid jq butchering the numbers
        TZ= ./pcap2mysql-log $f > $FILE.actual
    else
        TZ= ./pcap2mysql-log $f | jq 'sort_by (.Address)' > $FILE.actual
    fi
    ./pcap2mysql-summaries $FILE.actual > $FILE.txt.actual
    if [ ! -f $FILE.expected ]
    then
        cp $FILE.actual $FILE.expected
    fi
    if [ ! -f $FILE.txt.expected ]
    then
        cp $FILE.txt.actual $FILE.txt.expected
    fi
    diff -q $FILE.expected $FILE.actual || (echo Failed diff $FILE.expected $FILE.actual && exit 1)
    diff -q $FILE.txt.expected $FILE.txt.actual || (echo Failed diff $FILE.txt.expected $FILE.txt.actual && exit 1)
done


FILE=test/captures/compressed.raw
TZ= ./pcap2mysql-log test/captures/compressed.pcap --raw-data > $FILE.actual
if [ ! -f $FILE.expected ]
then
    cp $FILE.actual $FILE.expected
fi
diff -q $FILE.expected $FILE.actual || (echo Failed diff $FILE.expected $FILE.actual && exit 1)
