package streamfactory

import (
	"sync"

	gpkt "github.com/colinnewell/pcap2mysql-log/internal/gopacket"
	"github.com/colinnewell/pcap2mysql-log/internal/reader"

	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly"
)

type ConversationReader interface {
	ReadStream(r reader.Stream, a, b gopacket.Flow)
}

type MySQLStreamFactory struct {
	Reader ConversationReader
	wg     sync.WaitGroup
}

func (f *MySQLStreamFactory) New(a, b gopacket.Flow) tcpassembly.Stream {
	r := gpkt.NewReaderStream()
	f.wg.Add(1)
	go func() {
		f.Reader.ReadStream(&r, a, b)
		f.wg.Done()
	}()
	return &r
}

func (f *MySQLStreamFactory) Wait() {
	f.wg.Wait()
}
