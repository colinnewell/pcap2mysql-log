package packet_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/colinnewell/pcap2mysql-log/pkg/mysql/packet"
)

func TestSplit(t *testing.T) {
	sample := []byte{3, 0, 0, 0, 0x32, 0x33, 0x31, 4, 0, 0, 1, 0x20, 0x20, 0x20, 0x20, 5}

	split, remainder := splitPacket(sample)
	expected := [][]byte{
		{3, 0, 0, 0, 0x32, 0x33, 0x31},
		{4, 0, 0, 1, 0x20, 0x20, 0x20, 0x20},
	}
	if diff := cmp.Diff(split, expected); diff != "" {
		t.Fatalf("Split doesn't match (-got +expected):\n%s\n", diff)
	}
	expectedRemainder := []byte{5}
	if diff := cmp.Diff(remainder, expectedRemainder); diff != "" {
		t.Fatalf("Remainder doesn't match (-got +expected):\n%s\n", diff)
	}
}

func TestSplit2(t *testing.T) {
	sample := []byte{3, 0, 0, 0, 0x32, 0x33, 0x31, 4, 0, 0, 1, 0x20, 0x20, 0x20, 0x20, 0xf0, 0, 0, 0, 0}

	split, remainder := splitPacket(sample)
	expected := [][]byte{
		{3, 0, 0, 0, 0x32, 0x33, 0x31},
		{4, 0, 0, 1, 0x20, 0x20, 0x20, 0x20},
	}
	if diff := cmp.Diff(split, expected); diff != "" {
		t.Fatalf("Split doesn't match (-got +expected):\n%s\n", diff)
	}
	expectedRemainder := []byte{0xf0, 0, 0, 0, 0}
	if diff := cmp.Diff(remainder, expectedRemainder); diff != "" {
		t.Fatalf("Remainder doesn't match (-got +expected):\n%s\n", diff)
	}
}

func TestSplitNoRemainder(t *testing.T) {
	sample := []byte{3, 0, 0, 0, 0x32, 0x33, 0x31, 4, 0, 0, 1, 0x20, 0x20, 0x20, 0x20}

	split, remainder := splitPacket(sample)
	expected := [][]byte{
		{3, 0, 0, 0, 0x32, 0x33, 0x31},
		{4, 0, 0, 1, 0x20, 0x20, 0x20, 0x20},
	}
	if diff := cmp.Diff(split, expected); diff != "" {
		t.Fatalf("Split doesn't match (-got +expected):\n%s\n", diff)
	}
	expectedRemainder := []byte{}
	if diff := cmp.Diff(remainder, expectedRemainder); diff != "" {
		t.Fatalf("Remainder doesn't match (-got +expected):\n%s\n", diff)
	}
}

// splitPacket takes a blob of data and divides it up into MySQL packets.  This
// allows for data captured to be sent to regular parsing routines in a way
// that allows them to just consider a packet at a time.  Note that it doesn't
// really do any validation.
// Returns a list of packets, plus whatever data appears to remain.
func splitPacket(data []byte) ([][]byte, []byte) {
	s := splitter{}
	m := packet.MySQLPacketWriter{Receiver: &s}
	read, _ := m.Write(data)
	return s.packets, data[read:]
}

type splitter struct {
	packets [][]byte
}

func (s *splitter) Write(data []byte) (n int, err error) {
	s.packets = append(s.packets, data)
	return len(data), nil
}
