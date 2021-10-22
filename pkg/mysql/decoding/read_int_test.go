package decoding

import (
	"bytes"
	"testing"
)

func TestReadLenEncInt(t *testing.T) {
	expected := uint64(1)
	got, null, err := readLenEncInt(bytes.NewBuffer([]byte{1}))
	if err != nil {
		t.Fatal(err)
	}
	if expected != got {
		t.Fatal("Wrong answer")
	}
	if null {
		t.Fatal("Should not be null")
	}
}

func TestReadLenEncInt16(t *testing.T) {
	expected := uint64(256)
	got, _, err := readLenEncInt(bytes.NewBuffer([]byte{0xfc, 0, 1}))
	if err != nil {
		t.Fatal(err)
	}
	if expected != got {
		t.Fatalf("Wrong answer expected %d got %d", expected, got)
	}
}

func TestReadLenEncInt32(t *testing.T) {
	expected := uint64(65536)
	got, _, err := readLenEncInt(bytes.NewBuffer([]byte{0xfd, 0, 0, 1, 1}))
	if err != nil {
		t.Fatal(err)
	}
	if expected != got {
		t.Fatalf("Wrong answer expected %d got %d", expected, got)
	}
}

func TestReadLenEncInt64(t *testing.T) {
	expected := uint64(1)
	got, _, err := readLenEncInt(bytes.NewBuffer([]byte{0xfe, 1, 0, 0, 0, 0, 0, 0, 0}))
	if err != nil {
		t.Fatal(err)
	}
	if expected != got {
		t.Fatalf("Wrong answer expected %d got %d", expected, got)
	}
}

func TestReadLenEncBug(t *testing.T) {
	expected := uint64(110001)
	b := bytes.NewBuffer([]byte{
		0xfd, 0xb1, 0xad, 0x01,
	})
	got, _, err := readLenEncInt(b)
	if err != nil {
		t.Fatal(err)
	}
	if expected != got {
		t.Fatalf("Wrong answer expected %d got %d", expected, got)
	}
}
