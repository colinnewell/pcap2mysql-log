package packet_test

import (
	"bytes"
	"io"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/colinnewell/pcap2mysql-log/pkg/mysql/packet"
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
	if err != io.EOF {
		t.Fatal(err)
	}
}

func TestCopyAwkwardRead(t *testing.T) {
	b := bytes.NewBuffer([]byte{3, 0, 0, 0, 0x32, 0x33, 0x31, 4, 0, 0, 1, 0x20, 0x20, 0x20, 0x20})

	s := splitter{}
	n, err := packet.Copy(&twoByteReader{b}, &s)
	t.Log(n)
	t.Log(err)
	expected := [][]byte{
		{3, 0, 0, 0, 0x32, 0x33, 0x31},
		{4, 0, 0, 1, 0x20, 0x20, 0x20, 0x20},
	}
	if diff := cmp.Diff(s.packets, expected); diff != "" {
		t.Errorf("Writes don't match (-got +expected):\n%s\n", diff)
	}
	if err != io.EOF {
		t.Error(err)
	}
}

type twoByteReader struct {
	B *bytes.Buffer
}

func (r *twoByteReader) Read(p []byte) (n int, err error) {
	if len(p) > 2 {
		return r.B.Read(p[0:2])
	}
	return r.B.Read(p)
}
