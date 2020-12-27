package packet_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/colinnewell/pcap2mysql-log/internal/mysql/packet"
)

func TestSplit(t *testing.T) {
	sample := []byte{3, 0, 0, 0, 0x32, 0x33, 0x31, 4, 0, 0, 1, 0x20, 0x20, 0x20, 0x20, 5}

	split, remainder := packet.SplitPacket(sample)
	expected := [][]byte{
		{3, 0, 0, 0, 0x32, 0x33, 0x31},
		{4, 0, 0, 1, 0x20, 0x20, 0x20, 0x20},
	}
	if diff := cmp.Diff(split, expected); diff != "" {
		t.Fatalf("Split doesn't match (-got +expected):\n%s\n", diff)
	}
	expected_remainder := []byte{5}
	if diff := cmp.Diff(remainder, expected_remainder); diff != "" {
		t.Fatalf("Remainder doesn't match (-got +expected):\n%s\n", diff)
	}
}

func TestSplit2(t *testing.T) {
	sample := []byte{3, 0, 0, 0, 0x32, 0x33, 0x31, 4, 0, 0, 1, 0x20, 0x20, 0x20, 0x20, 0xf0, 0, 0, 0, 0}

	split, remainder := packet.SplitPacket(sample)
	expected := [][]byte{
		{3, 0, 0, 0, 0x32, 0x33, 0x31},
		{4, 0, 0, 1, 0x20, 0x20, 0x20, 0x20},
	}
	if diff := cmp.Diff(split, expected); diff != "" {
		t.Fatalf("Split doesn't match (-got +expected):\n%s\n", diff)
	}
	expected_remainder := []byte{0xf0, 0, 0, 0, 0}
	if diff := cmp.Diff(remainder, expected_remainder); diff != "" {
		t.Fatalf("Remainder doesn't match (-got +expected):\n%s\n", diff)
	}
}

func TestSplitNoRemainder(t *testing.T) {
	sample := []byte{3, 0, 0, 0, 0x32, 0x33, 0x31, 4, 0, 0, 1, 0x20, 0x20, 0x20, 0x20}

	split, remainder := packet.SplitPacket(sample)
	expected := [][]byte{
		{3, 0, 0, 0, 0x32, 0x33, 0x31},
		{4, 0, 0, 1, 0x20, 0x20, 0x20, 0x20},
	}
	if diff := cmp.Diff(split, expected); diff != "" {
		t.Fatalf("Split doesn't match (-got +expected):\n%s\n", diff)
	}
	expected_remainder := []byte{}
	if diff := cmp.Diff(remainder, expected_remainder); diff != "" {
		t.Fatalf("Remainder doesn't match (-got +expected):\n%s\n", diff)
	}
}
