package main

import (
	"github.com/spf13/pflag"

	"github.com/colinnewell/pcap-cli/cli"

	"github.com/colinnewell/pcap2mysql-log/pkg/mysql/decoding"
)

func main() {
	var intermediateData, noSort, rawData, verbose bool

	pflag.BoolVar(&intermediateData, "intermediate-data", false, "Emit the data before processing")
	pflag.BoolVar(&rawData, "raw-data", false, "Include the raw packet data")
	pflag.BoolVar(&noSort, "no-sort", false, "Don't sort packets by time")
	pflag.BoolVar(&verbose, "verbose", false, "Verbose about things errors")

	r := decoding.New(&intermediateData, &rawData, &verbose, &noSort)
	cli.Main("", r)
}
