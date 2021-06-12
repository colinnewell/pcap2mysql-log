package packet_test

import (
	"bytes"
	"io"
	"testing"

	"github.com/colinnewell/pcap2mysql-log/pkg/mysql/packet"
	"github.com/google/go-cmp/cmp"
)

func TestNoCompression(t *testing.T) {
	expected := []byte{
		0x09, 0x00, 0x00, 0x00, 0x03, 0x53, 0x45, 0x4c, 0x45, 0x43, 0x54, 0x20, 0x31, // -- 0xSE,LECT 1
	}

	input := []byte{
		0x0d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x03, 0x53, 0x45, 0x4c, 0x45, // ............SELE
		0x43, 0x54, 0x20, 0x31, // 0xCT, 1
	}

	var b bytes.Buffer
	d := packet.MySQLPacketDecompressor{Receiver: &b}
	if _, err := d.Write(input); err != nil {
		t.Fatal(err)
	}

	if diff := cmp.Diff(b.Bytes(), expected); diff != "" {
		t.Fatalf("Decompressed version doesn't match (-got +expected):\n%s\n", diff)
	}
}

func TestOnePacketExample(t *testing.T) {
	expected := []byte{
		0x2e, 0x00, 0x00, 0x00, 0x03, 0x73, 0x65, 0x6c, 0x65, 0x63, 0x74, 0x20, 0x22, 0x30, 0x31, 0x32, // .....select "012
		0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, // 3456789012345678
		0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, // 9012345678901234
		0x35, 0x22, // 5"
	}

	input := []byte{
		0x22, 0x00, 0x00, 0x00, 0x32, 0x00, 0x00, 0x78, 0x9c, 0xd3, 0x63, 0x60, 0x60, 0x60, 0x2e, 0x4e, // "...2..x..c```.N
		0xcd, 0x49, 0x4d, 0x2e, 0x51, 0x50, 0x32, 0x30, 0x34, 0x32, 0x36, 0x31, 0x35, 0x33, 0xb7, 0xb0, // .IM.QP20426153..
		0xc4, 0xcd, 0x52, 0x02, 0x00, 0x0c, 0xd1, 0x0a, 0x6c, // ..R.....l
	}

	var b bytes.Buffer
	d := packet.MySQLPacketDecompressor{Receiver: &b}
	if _, err := d.Write(input); err != nil && err != io.EOF {
		t.Fatal(err)
	}

	if diff := cmp.Diff(b.Bytes(), expected); diff != "" {
		t.Fatalf("Decompressed version doesn't match (-got +expected):\n%s\n", diff)
	}
}

func TestMultiplePacketsDecompress(t *testing.T) {
	expected := [][]byte{
		{0x01, 0x00, 0x00, 0x01, 0x01},
		{
			0x25, 0x0, 0x0, 0x2, 0x3, 0x64, 0x65, 0x66, 0x0, 0x0, 0x0,
			0xf, 0x72, 0x65, 0x70, 0x65, 0x61, 0x74, 0x28, 0x22, 0x61,
			0x22, 0x2c, 0x20, 0x35, 0x30, 0x29, 0x0, 0xc, 0x8, 0x0,
			0x32, 0x0, 0x0, 0x0, 0xfd, 0x1, 0x0, 0x1f, 0x0, 0x0,
		},
		{0x05, 0x00, 0x00, 0x03, 0xfe, 0x00, 0x00, 0x02, 0x00},
		{
			0x33, 0x0, 0x0, 0x4, 0x32, 0x61, 0x61, 0x61, 0x61, 0x61,
			0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
			0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
			0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
			0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
			0x61, 0x61, 0x61, 0x61, 0x61,
		},
		{0x05, 0x00, 0x00, 0x05, 0xfe, 0x00, 0x00, 0x02, 0x00},
	}

	input := []byte{
		0x4a, 0x00, 0x00, 0x01, 0x77, 0x00, 0x00, 0x78, 0x9c, 0x63, 0x64, 0x60, 0x60, 0x64, 0x54, 0x65, // J...w..x.cd``dTe
		0x60, 0x60, 0x62, 0x4e, 0x49, 0x4d, 0x63, 0x60, 0x60, 0xe0, 0x2f, 0x4a, 0x2d, 0x48, 0x4d, 0x2c, // ``bNIMc``./J-HM,
		0xd1, 0x50, 0x4a, 0x54, 0xd2, 0x51, 0x30, 0x35, 0xd0, 0x64, 0xe0, 0xe1, 0x60, 0x30, 0x02, 0x8a, // .PJT.Q05.d..`0..
		0xff, 0x65, 0x64, 0x90, 0x67, 0x60, 0x60, 0x65, 0x60, 0x60, 0xfe, 0x07, 0x54, 0xcc, 0x60, 0xcc, // .ed.g``e``..T.`.
		0xc0, 0xc0, 0x62, 0x94, 0x48, 0x32, 0x00, 0xea, 0x67, 0x05, 0xeb, 0x07, 0x00, 0x8d, 0xf9, 0x1c, // ..b.H2..g.......
		0x64, // d
	}

	s := splitter{}
	d := packet.MySQLPacketDecompressor{Receiver: &s}
	if _, err := d.Write(input); err != nil && err != io.EOF {
		t.Fatal(err)
	}

	if diff := cmp.Diff(s.packets, expected); diff != "" {
		t.Fatalf("Decompressed version doesn't match (-got +expected):\n%s\n", diff)
	}
}