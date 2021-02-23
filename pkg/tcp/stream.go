package tcp

import "time"

type Stream interface {
	Read(p []byte) (n int, err error)
	Seen() (time.Time, error)
}
