module github.com/colinnewell/pcap2mysql-log

go 1.16

require (
	github.com/colinnewell/pcap-cli v0.0.5
	github.com/google/go-cmp v0.6.0
	github.com/google/gopacket v1.1.19
	github.com/pkg/errors v0.9.1
	github.com/spf13/pflag v1.0.5
	golang.org/x/net v0.36.0 // indirect
)

// replace github.com/colinnewell/pcap-cli => ../pcap-cli
