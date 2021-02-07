# pcap2mysql-log

This is a work in progress and doesn't do anything too much yet.

The intention is to take a packet capture file and turn it into some sort of
text based human & machine readable transcript of MySQL communications.

Since creating [pcap2har](https://github.com/colinnewell/pcap2har) seemed so
easy, mostly just wiring up existing libraries, I figured how hard could this
be?  A fair bit more it turns out.

For context pcap2har reads HTTP requests and responses and uses the existing
libraries.  With MySQL we need to do the same kind of thing, looking at both
sides of the communication, but libraries tend to be sending one way, and
receiving the other, rather than reading both ways.

Where is the program so far?  The current goal is to read a file containing the
packet data and emit a quick transcript that demonstrates we've grokked it's
contents correctly.  It's very crude so far, but seems to be heading in the
right direction.

    make
    ./pcap2mysql-log --to 48508-3306.test --from 3306-48508.test

Right now the program isn't reading a pcap file, instead it's reading raw data
from files.  I've been generating them by bodging pcap2har to dump out raw
connection data, but this could be generated in various ways.

Wireshark is as ever a useful reference for looking at what's going on.  Both
by looking at packet captures, and by looking at it's code.

## References

* Wireshark's [packet-mysql.c](https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-mysql.c)
* https://github.com/orderbynull/lottip it's code got me started.
* https://mariadb.com/kb/en/result-set-packets/
* https://dev.mysql.com/doc/internals/en/integer.html#packet-Protocol::FixedLengthInteger
