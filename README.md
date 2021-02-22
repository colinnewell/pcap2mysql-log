# pcap2mysql-log

This is a work in progress and doesn't do anything too much yet.

The intention is to take a packet capture file and turn it into some sort of
text based human & machine readable transcript of MySQL communications.

    pcap2mysql-log test/captures/dump00.pcap --server-ports 3306

It is currently being developed as a quick tool to aid development, and is only
really being developed as needed.  To develop it properly it really needs a lot
of effort, and so far that isn't being expended on this.

## Building

This program requires libpcap to build and run.  On Linux you typically install
a development version of the library like this on Debian and Ubuntu variants:

	sudo apt install libpcap-dev

On Windows download and install npcap from https://nmap.org/npcap/.  The
regular installer is sufficient, you shouldn't need the SDK.

On Mac's/BSD the library bindings required should be there out of the box
(no further action required).

Note that it's assumed you have Go installed, and also make (without make look
at the commands in the Makefile, that is mostly being used for convenience
rather than because things are particularly complex).

	git clone https://github.com/colinnewell/pcap2mysql-log.git
	cd pcap2mysql-log
	make
	sudo make install


## Usage of pcap2mysql-log:

        --server-ports int32Slice   Server ports (default [])
        --version                   Display program version

Reading a pcap file:

	sudo tcpdump port 3306 -w packets.dump
    ./pcap2mysql-log packets.dump

Note that the `--server-ports` option is useful for narrowing down the traffic
the program process from the packet capture.  If you've captured web traffic as
well as MySQL you can speed it up and ensure it won't get confused by the other
traffic.

## General notes

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


Wireshark is as ever a useful reference for looking at what's going on.  Both
by looking at packet captures, and by looking at it's code.

## Thanks

A big thank you to Nadja for helping figure out the MySQL traffic and starting
some of the foundational code when it was at a nascent stage.  Her help got it
going at a point where I was feeling blocked.

Wireshark has provided a useful reference point for checking my results.

The Lottip program also gave me confidence that this sort of thing could be
done.

## References

* Wireshark's [packet-mysql.c](https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-mysql.c)
* https://github.com/orderbynull/lottip it's code got me started.
* https://mariadb.com/kb/en/result-set-packets/
* https://dev.mysql.com/doc/internals/en/integer.html#packet-Protocol::FixedLengthInteger
