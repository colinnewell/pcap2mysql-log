package decoding

import "testing"

func TestIsTextBinary(t *testing.T) {
	examples := [][]byte{
		{1, 2, 3},
	}

	for _, v := range examples {
		if isText(v) {
			t.Errorf("Should not be marked as text: %v\n", v)
		}
	}
}

func TestIsTextText(t *testing.T) {
	examples := [][]byte{
		[]byte("carrots are wonderful"),
	}

	for _, v := range examples {
		if !isText(v) {
			t.Errorf("Should be marked as text: %v\n", v)
		}
	}
}
