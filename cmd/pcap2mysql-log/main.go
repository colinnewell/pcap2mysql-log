package main

import (
	"encoding/json"
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
	var displayVersion, rawData bool
	var serverPorts []int32

	pflag.BoolVar(&displayVersion, "version", false, "Display program version")
	pflag.BoolVar(&rawData, "raw-data", false, "Include the raw packet data")
	pflag.Int32SliceVar(&serverPorts, "server-ports", []int32{}, "Server ports")
	pflag.Parse()

	buildVersion := "unknown"
	if bi, ok := debug.ReadBuildInfo(); ok {
		// NOTE: right now this probably always returns (devel).  Hopefully
		// will improve with new versions of Go.  It might be neat to add
		// dep info too at some point since that's part of the build info.
		buildVersion = bi.Main.Version
	}

	if displayVersion {
		fmt.Printf("Version: %s %s\n", Version, buildVersion)
		return
	}

	files := pflag.Args()

	if len(files) > 0 {
		processHarFiles(serverPorts, files, rawData)
		return
	}

	fmt.Println("Specify pcap files to process")
}

func processHarFiles(serverPorts []int32, files []string, rawData bool) {
	r := decoding.New(rawData)
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
				// FIXME: could discriminate here to minimise issues with processing.
				// NOTE: just pushing all TCP through it on the basis it might
				// be http.
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
	c := r.GetConnections()
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
