module github.com/colinnewell/pcap2mysql-log

go 1.23.0

toolchain go1.24.1

require (
	github.com/colinnewell/pcap-cli v0.0.5
	github.com/google/go-cmp v0.5.6
	github.com/google/gopacket v1.1.19
	github.com/pkg/errors v0.9.1
	github.com/spf13/pflag v1.0.6
)

require (
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	golang.org/x/net v0.23.0 // indirect
	golang.org/x/sys v0.32.0 // indirect
	golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1 // indirect
)

// replace github.com/colinnewell/pcap-cli => ../pcap-cli
