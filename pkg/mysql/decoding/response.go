package decoding

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/colinnewell/pcap2mysql-log/pkg/mysql/packet"
	"github.com/colinnewell/pcap2mysql-log/pkg/mysql/structure"
)

type readState byte

const (
	start readState = iota
	fieldInfo
	data

	encodedNull  = 0xfb
	encoded16bit = 0xfc
	encoded32bit = 0xfd
	encoded64bit = 0xfe
)

// ResponseDecoder - dealing with the response.
type ResponseDecoder struct {
	Emit Emitter

	Fields  []structure.ColumnInfo
	State   readState
	Results [][]string
}

func (m *ResponseDecoder) decodeGreeting(p []byte) error {
	protocol := p[0]
	b := bytes.NewBuffer(p[1:])
	version, err := readNulString(b)
	if err != nil {
		return err
	}

	// not really interested in all the data here right now.
	// skipping connection id + various other bits.
	//nolint:gomnd
	b.Next(9 + 4)
	capabilityBytes := [4]byte{}
	if n, err := b.Read(capabilityBytes[0:2]); err != nil || n < 2 {
		if err != nil {
			return err
		}
		return fmt.Errorf("only read %d bytes", b.Len())
	}
	collation, err := b.ReadByte()
	if err != nil {
		return err
	}
	if n, err := b.Read(capabilityBytes[2:4]); err != nil || n < 2 {
		if err != nil {
			return err
		}
		return fmt.Errorf("only read %d bytes", b.Len())
	}
	// FIXME: not sure if this is the best way to decode the capability info
	capabilities := binary.LittleEndian.Uint32(capabilityBytes[:])
	m.Emit.Transmission(structure.Greeting{
		Capabilities: capabilities,
		Collation:    collation,
		Protocol:     protocol,
		Type:         "Greeting",
		Version:      version,
	})
	return nil
}

func (m *ResponseDecoder) decodeOK(p []byte) error {
	ok := structure.OKResponse{
		Type: "OK",
	}
	b := bytes.NewBuffer(p)
	for _, val := range []*uint64{&ok.AffectedRows, &ok.LastInsertID} {
		v, err := readLenEncInt(b)
		if err != nil {
			return err
		}
		*val = v
	}
	var serverStatus uint16
	// NOTE: this may not be quite right.  Capabilities of the
	// connection will affect the structure of the OK.
	// also note that the EOF (0xfe) packet has the same basic structure
	// too now.
	for _, val := range []*uint16{&serverStatus, &ok.WarningCount} {
		if err := binary.Read(b, binary.LittleEndian, val); err != nil {
			return err
		}
	}
	ok.ServerStatus = structure.StatusFlags(serverStatus)
	m.Emit.Transmission(ok)
	return nil
}

//nolint:funlen
func (m *ResponseDecoder) Write(p []byte) (int, error) {
	// FIXME: check how much data we have
	switch m.State {
	case start:
		if p[packet.PacketNo] == 0 {
			err := m.decodeGreeting(p[packet.HeaderLen:])
			if err != nil {
				return 0, err
			}
			break
		}
		switch structure.ResponseType(p[packet.HeaderLen]) {
		case structure.MySQLError:
			m.decodeError(p)
		case structure.MySQLEOF:
			// check if it's really an EOF
			m.Emit.Transmission(structure.Response{Type: "EOF"})
		case structure.MySQLOK:
			err := m.decodeOK(p[packet.HeaderLen+1:])
			if err != nil {
				return 0, err
			}
		case structure.MySQLLocalInfile:
			// check if it's really an EOF
			m.Emit.Transmission(structure.Response{Type: "In file"})
		default:
			m.State = fieldInfo
			m.Fields = []structure.ColumnInfo{}
			m.Results = [][]string{}
		}
	case data:
		if structure.ResponseType(p[packet.HeaderLen]) == structure.MySQLEOF {
			m.FlushResponse()
			m.ResetState()
			break
		}

		r := make([]string, len(m.Fields))

		b := bytes.NewBuffer(p[packet.HeaderLen:])

		for i := range r {
			var err error

			r[i], err = readLenEncString(b)

			if err != nil {
				return 0, err
			}
		}
		m.Results = append(m.Results, r)

	case fieldInfo:
		if structure.ResponseType(p[packet.HeaderLen]) == structure.MySQLEOF {
			m.State = data
			break
		}

		buf := bytes.NewBuffer(p[packet.HeaderLen:])
		field := structure.ColumnInfo{}

		for _, val := range []*string{
			&field.Catalog,
			&field.Schema,
			&field.TableAlias,
			&field.Table,
			&field.ColumnAlias,
			&field.Column,
		} {
			s, err := readLenEncString(buf)

			if err != nil {
				return 0, err
			}

			*val = s
		}

		if err := binary.Read(buf, binary.LittleEndian, &field.TypeInfo); err != nil {
			return 0, err
		}

		m.Fields = append(m.Fields, field)
	}

	return len(p), nil
}

func (m *ResponseDecoder) FlushResponse() {
	if m.State == start {
		// nothing banked up.
		return
	}
	// flush out all the data we have stored up.
	m.Emit.Transmission(structure.Response{
		Type:    "SQL results",
		Columns: m.Fields,
		Results: m.Results,
	})
}

func (m *ResponseDecoder) ResetState() {
	m.State = start
}

func (m *ResponseDecoder) decodeError(p []byte) {
	errorMsg := structure.ErrorResponse{Type: "Error"}
	if len(p) > packet.HeaderLen+3 {
		errorCode := binary.LittleEndian.Uint16(p[packet.HeaderLen+1:])
		errorMsg.Code = errorCode
		if errorCode == packet.InProgress {
			// FIXME: progress
			errorMsg.Message = "Progress"
		} else {
			data := p[packet.HeaderLen+3:]
			if data[0] == '#' {
				errorMsg.State = string(data[1:6])
				data = data[6:]
			}
			errorMsg.Message = string(data)
		}
	}
	m.Emit.Transmission(errorMsg)
}

func readLenEncString(buf *bytes.Buffer) (string, error) {
	count, err := buf.ReadByte()

	if err != nil {
		return "", err
	}

	s := string(buf.Next(int(count)))

	if len(s) < int(count) {
		return "", fmt.Errorf("only read %d bytes", len(s))
	}

	return s, nil
}

func readNulString(buf *bytes.Buffer) (string, error) {
	vb, err := buf.ReadBytes(0)
	if err != nil {
		return "", err
	}
	return string(vb[:len(vb)-1]), nil
}

func readLenEncInt(buf io.Reader) (uint64, error) {
	var first [1]byte
	if _, err := buf.Read(first[:]); err != nil {
		return 0, err
	}
	l := first[0]

	switch l {
	case encodedNull:
		// FIXME: actually null, not sure how to express this.
		return 0, nil
	case encoded16bit:
		var val uint16
		if err := binary.Read(buf, binary.LittleEndian, &val); err != nil {
			return 0, err
		}
		return uint64(val), nil
	case encoded32bit:
		var val uint32
		if err := binary.Read(buf, binary.LittleEndian, &val); err != nil {
			return 0, err
		}
		return uint64(val), nil
	case encoded64bit:
		var val uint64
		if err := binary.Read(buf, binary.LittleEndian, &val); err != nil {
			return 0, err
		}
		return val, nil
	default:
		return uint64(l), nil
	}
}

// func readFixedString(buf *bytes.Buffer, length int) (string, error) {
// 	b := buf.Next(length)
// 	if len(b) < length {
// 		return "", fmt.Errorf("only read %d bytes", len(b))
// 	}
// 	return string(b), nil
// }
