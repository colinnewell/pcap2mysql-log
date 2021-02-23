package tcp_test

import (
	"testing"

	"github.com/colinnewell/pcap2mysql-log/internal/reader"
	"github.com/colinnewell/pcap2mysql-log/pkg/tcp"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
)

func TestHTTPStreamRead(t *testing.T) {
	r := reader.New()
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
	r.GetConversations()
	// FIXME: get this reliable and test properly.
	// this is a pretty crude test, just checking we have
	// managed to do something, rather than the integrity.
	// if len(c) != 13 {
	// 	t.Errorf("Should have read 13 http conversations: read %d", len(c))
	// }
}
