#!/bin/bash -e

TZ= ./pcap2mysql-log test/captures/insecure.pcap > test/captures/insecure.actual
diff test/captures/insecure.expected test/captures/insecure.actual
