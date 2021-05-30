package tcp_test

import (
	"testing"

	"github.com/colinnewell/pcap2mysql-log/pkg/mysql/decoding"
	"github.com/colinnewell/pcap2mysql-log/pkg/tcp"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
)

func TestHTTPStreamRead(t *testing.T) {
	r := decoding.New(false, false)
	streamFactory := &tcp.StreamFactory{
		Reader: r,
	}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)

	if handle, err := pcap.OpenOffline("../../test/captures/insecure.pcap"); err != nil {
		t.Error(err)
	} else {
		defer handle.Close()
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			if tcp, ok := packet.TransportLayer().(*layers.TCP); ok {
				assembler.AssembleWithTimestamp(
					packet.NetworkLayer().NetworkFlow(),
					tcp, packet.Metadata().Timestamp)
			}
		}
	}
	assembler.FlushAll()
	c := r.GetConnections(false)
	// FIXME: test in more detail.
	expected := 29
	if len(c) != expected {
		t.Errorf("Should have read %d mysql connections: read %d", expected, len(c))
	}
}
