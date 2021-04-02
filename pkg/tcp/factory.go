package tcp

import (
	"sync"

	gpkt "github.com/colinnewell/pcap2mysql-log/internal/gopacket"

	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly"
)

type ConnectionReader interface {
	ReadStream(r Stream, a, b gopacket.Flow)
}

type StreamFactory struct {
	Reader ConnectionReader
	wg     sync.WaitGroup
}

func (f *StreamFactory) New(a, b gopacket.Flow) tcpassembly.Stream {
	r := gpkt.NewReaderStream()
	f.wg.Add(1)
	go func() {
		defer f.wg.Done()
		f.Reader.ReadStream(&r, a, b)
	}()
	return &r
}

func (f *StreamFactory) Wait() {
	f.wg.Wait()
}
