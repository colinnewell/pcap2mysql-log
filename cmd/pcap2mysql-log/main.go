package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"runtime/debug"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"github.com/spf13/pflag"

	"github.com/colinnewell/pcap2mysql-log/internal/mysql/decoding"
	"github.com/colinnewell/pcap2mysql-log/internal/mysql/packet"
	"github.com/colinnewell/pcap2mysql-log/internal/reader"
	"github.com/colinnewell/pcap2mysql-log/internal/streamfactory"
)

// MySQLConnection is for reading the two sides of the connection.
type MySQLConnection struct {
	Request  io.Reader
	Response io.Reader
}

func main() {
	var displayVersion bool
	var to, from string
	var serverPorts []int32

	pflag.BoolVar(&displayVersion, "version", false, "Display program version")
	pflag.StringVar(&to, "to", "", "Traffic to the mysql server")
	pflag.StringVar(&from, "from", "", "Traffic from the mysql server")
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
		processHarFiles(serverPorts, files)
		return
	}

	// FIXME: check to and from are specified
	if len(files) == 0 && (to == "" || from == "") {
		log.Fatal("Must specify --to and --from files with traffic")
	}

	c := MySQLConnection{}

	f, err := os.Open(to)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	c.Request = f

	t, err := os.Open(from)
	if err != nil {
		// NOTE: complains about fatal + defer.  This code isn't great, but is
		// more for testing so not going to worry right now.
		//nolint:gocritic
		log.Fatal(err)
	}
	defer t.Close()

	c.Response = t

	if err := c.Read(); err != nil {
		log.Fatal(err)
	}
}

func processHarFiles(serverPorts []int32, files []string) {
	r := reader.New()
	streamFactory := &streamfactory.MySQLStreamFactory{
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
	c := r.GetConversations()
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

func (m *MySQLConnection) Read() error {
	fmt.Println("---- To")

	interpreter := decoding.MySQLRequest{}

	if _, err := packet.Copy(m.Request, &interpreter); err != nil {
		log.Println(err)
	}

	fmt.Println("---- From")

	response := decoding.MySQLresponse{}

	if _, err := packet.Copy(m.Response, &response); err != nil {
		return err
	}

	return nil
}
