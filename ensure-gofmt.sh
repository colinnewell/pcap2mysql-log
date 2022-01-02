#!/bin/sh
list=$(gofmt -l -s .)
echo $list
if [ -n "$list" ]
then
    echo "Files need to be gofmt'd."
    for f in $list
    do
        echo $f:1:0: Need to run gofmt -w -s $f
    done
    exit 1
fi
