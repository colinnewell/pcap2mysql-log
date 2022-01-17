module github.com/colinnewell/pcap2mysql-log

go 1.16

require (
	github.com/colinnewell/pcap-cli v0.0.2
	github.com/google/go-cmp v0.5.6
	github.com/google/gopacket v1.1.19
	github.com/pkg/errors v0.9.1
	github.com/spf13/pflag v1.0.5
	golang.org/x/net v0.0.0-20200927032502-5d4f70055728 // indirect
	golang.org/x/sys v0.0.0-20210616094352-59db8d763f22 // indirect
	golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1 // indirect
)

// replace github.com/colinnewell/pcap-cli => ../pcap-cli
