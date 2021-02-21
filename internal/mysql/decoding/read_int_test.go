package decoding

import (
	"bytes"
	"testing"
)

func TestReadLenEncInt(t *testing.T) {
	expected := uint64(1)
	got, err := readLenEncInt(bytes.NewBuffer([]byte{1}))
	if err != nil {
		t.Fatal(err)
	}
	if expected != got {
		t.Fatal("Wrong answer")
	}
}

func TestReadLenEncInt16(t *testing.T) {
	expected := uint64(256)
	got, err := readLenEncInt(bytes.NewBuffer([]byte{0xfc, 0, 1}))
	if err != nil {
		t.Fatal(err)
	}
	if expected != got {
		t.Fatalf("Wrong answer expected %d got %d", expected, got)
	}
}

func TestReadLenEncInt32(t *testing.T) {
	expected := uint64(0x1000000)
	got, err := readLenEncInt(bytes.NewBuffer([]byte{0xfd, 0, 0, 0, 1}))
	if err != nil {
		t.Fatal(err)
	}
	if expected != got {
		t.Fatalf("Wrong answer expected %d got %d", expected, got)
	}
}

func TestReadLenEncInt64(t *testing.T) {
	expected := uint64(1)
	got, err := readLenEncInt(bytes.NewBuffer([]byte{0xfe, 1, 0, 0, 0, 0, 0, 0, 0}))
	if err != nil {
		t.Fatal(err)
	}
	if expected != got {
		t.Fatalf("Wrong answer expected %d got %d", expected, got)
	}
}
