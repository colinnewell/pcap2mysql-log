package packet_test

import (
	"bytes"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/colinnewell/pcap2mysql-log/internal/mysql/packet"
)

func TestCopy(t *testing.T) {
	b := bytes.NewBuffer([]byte{3, 0, 0, 0, 0x32, 0x33, 0x31, 4, 0, 0, 1, 0x20, 0x20, 0x20, 0x20, 5})

	s := splitter{}
	n, err := packet.Copy(b, &s)
	t.Log(n)
	t.Log(err)
	expected := [][]byte{
		{3, 0, 0, 0, 0x32, 0x33, 0x31},
		{4, 0, 0, 1, 0x20, 0x20, 0x20, 0x20},
	}
	if diff := cmp.Diff(s.packets, expected); diff != "" {
		t.Fatalf("Writes don't match (-got +expected):\n%s\n", diff)
	}
	if diff := cmp.Diff(err.Error(), "packet: incomplete packet"); diff != "" {
		t.Fatalf("Errors don't match (-got +expected):\n%s\n", diff)
	}
}

func TestCopyNoError(t *testing.T) {
	b := bytes.NewBuffer([]byte{3, 0, 0, 0, 0x32, 0x33, 0x31, 4, 0, 0, 1, 0x20, 0x20, 0x20, 0x20})

	s := splitter{}
	n, err := packet.Copy(b, &s)
	t.Log(n)
	t.Log(err)
	expected := [][]byte{
		{3, 0, 0, 0, 0x32, 0x33, 0x31},
		{4, 0, 0, 1, 0x20, 0x20, 0x20, 0x20},
	}
	if diff := cmp.Diff(s.packets, expected); diff != "" {
		t.Fatalf("Writes don't match (-got +expected):\n%s\n", diff)
	}
	if err != nil {
		t.Fatal(err)
	}
}
