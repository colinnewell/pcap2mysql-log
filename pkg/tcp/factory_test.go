package tcp_test

import (
	"testing"

	"github.com/colinnewell/pcap2mysql-log/pkg/mysql/decoding"
	"github.com/colinnewell/pcap2mysql-log/pkg/mysql/structure"
	"github.com/colinnewell/pcap2mysql-log/pkg/tcp"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
)

func TestHTTPStreamRead(t *testing.T) {
	completed := make(chan structure.Connection)
	r := decoding.New(false, false, false, false, completed)
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
	go func() {
		streamFactory.Wait()
		close(completed)
	}()
	actual := 0
	for range completed {
		actual++
	}
	// FIXME: test in more detail.
	expected := 29
	if actual != expected {
		t.Errorf("Should have read %d mysql connections: read %d", expected, actual)
	}
}
