package packet

import (
	"fmt"
	"io"
)

type MySQLPacketDecompressor struct {
	Receiver io.Writer
}

func (w *MySQLPacketDecompressor) Write(data []byte) (n int, err error) {
	compLength := mySQLPacketLength(data[:3])
	unCompLength := mySQLPacketLength(data[4:6])
	fmt.Printf("%x - %x\n", compLength, unCompLength)
	if unCompLength == 0 {
		// not compressed, just strip off the extra header
		n, err := w.Receiver.Write(data[7 : 7+compLength])
		return n + 7, err
	}

	return w.Receiver.Write(data)
}
