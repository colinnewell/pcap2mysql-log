package structure

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestFieldDetailString(t *testing.T) {
	var d FieldDetail = DETAIL_UNIQUE_KEY

	if diff := cmp.Diff(d.String(), "UNIQUE_KEY"); diff != "" {
		t.Fatalf("Stringified version doesn't match (-got +expected):\n%s\n", diff)
	}
}

func TestFieldDetailString2(t *testing.T) {
	var d FieldDetail = 16388

	if diff := cmp.Diff(d.String(), "UNIQUE_KEY|PART_KEY_FLAG"); diff != "" {
		t.Fatalf("Stringified version doesn't match (-got +expected):\n%s\n", diff)
	}
}
