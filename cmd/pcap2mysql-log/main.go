package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"runtime/debug"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"github.com/spf13/pflag"

	"github.com/colinnewell/pcap2mysql-log/pkg/mysql/decoding"
	"github.com/colinnewell/pcap2mysql-log/pkg/tcp"
)

func main() {
	var assemblyDebug, displayVersion, intermediateData, noSort, rawData, verbose bool
	var serverPorts []int32

	pflag.BoolVar(&assemblyDebug, "assembly-debug", false, "Debug log from the tcp assembly")
	pflag.BoolVar(&displayVersion, "version", false, "Display program version")
	pflag.BoolVar(&intermediateData, "intermediate-data", false, "Emit the data before processing")
	pflag.BoolVar(&rawData, "raw-data", false, "Include the raw packet data")
	pflag.BoolVar(&noSort, "no-sort", false, "Don't sort packets by time")
	pflag.BoolVar(&verbose, "verbose", false, "Vocalise error info")
	pflag.Int32SliceVar(&serverPorts, "server-ports", []int32{}, "Server ports")
	pflag.Parse()

	if assemblyDebug {
		if err := flag.Set("assembly_debug_log", "true"); err != nil {
			log.Fatal(err)
		}
	}

	if displayVersion {
		buildVersion := "unknown"
		if bi, ok := debug.ReadBuildInfo(); ok {
			// NOTE: right now this probably always returns (devel).  Hopefully
			// will improve with new versions of Go.  It might be neat to add
			// dep info too at some point since that's part of the build info.
			buildVersion = bi.Main.Version
		}

		fmt.Printf("Version: %s %s\n", Version, buildVersion)
		return
	}

	files := pflag.Args()

	if len(files) > 0 {
		processHarFiles(serverPorts, files, intermediateData, noSort, rawData, verbose)
		return
	}

	fmt.Println("Specify pcap files to process")
}

func processHarFiles(serverPorts []int32, files []string, intermediateData bool, noSort bool, rawData bool, verbose bool) {
	r := decoding.New(intermediateData, rawData, verbose)
	streamFactory := &tcp.StreamFactory{
		Reader: r,
	}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)

	for _, filename := range files {
		if handle, err := pcap.OpenOffline(filename); err != nil {
			log.Fatal(err)
		} else {
			defer handle.Close()
			packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

			for packet := range packetSource.Packets() {
				if tcp, ok := packet.TransportLayer().(*layers.TCP); ok {
					if allowPort(serverPorts, tcp) {
						assembler.AssembleWithTimestamp(
							packet.NetworkLayer().NetworkFlow(),
							tcp, packet.Metadata().Timestamp)
					}
				}
			}
		}
	}

	assembler.FlushAll()

	streamFactory.Wait()
	c := r.GetConnections(noSort)
	bytes, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		log.Println(err)
		return
	}
	fmt.Println(string(bytes))
}

func allowPort(serverPorts []int32, packet *layers.TCP) bool {
	if len(serverPorts) == 0 {
		return true
	}

	for _, port := range serverPorts {
		if packet.SrcPort == layers.TCPPort(port) ||
			packet.DstPort == layers.TCPPort(port) {
			return true
		}
	}

	return false
}
