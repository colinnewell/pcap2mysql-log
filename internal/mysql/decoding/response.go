package decoding

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/colinnewell/pcap2mysql-log/internal/mysql/packet"
	"github.com/colinnewell/pcap2mysql-log/internal/types"
)

type readState byte

const (
	start readState = iota
	fieldInfo
	data
)

// ResponseDecoder - dealing with the response.
type ResponseDecoder struct {
	Emit types.Emitter

	Fields  []types.MySQLtypes
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
	m.Emit.Transmission(types.Greeting{
		Protocol:     protocol,
		Version:      version,
		Collation:    collation,
		Capabilities: capabilities,
	})
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
		switch types.ResponseType(p[packet.HeaderLen]) {
		case types.MySQLError:
			m.Emit.Transmission(types.Response{Type: "Error"})
		case types.MySQLEOF:
			// check if it's really an EOF
			m.Emit.Transmission(types.Response{Type: "EOF"})
		case types.MySQLOK:
			m.Emit.Transmission(types.Response{Type: "OK"})
		case types.MySQLLocalInfile:
			// check if it's really an EOF
			m.Emit.Transmission(types.Response{Type: "In file"})
		default:
			m.State = fieldInfo
			m.Fields = []types.MySQLtypes{}
			m.Results = [][]string{}
		}
	case data:
		if types.ResponseType(p[packet.HeaderLen]) == types.MySQLEOF {
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
		if types.ResponseType(p[packet.HeaderLen]) == types.MySQLEOF {
			m.State = data
			break
		}

		buf := bytes.NewBuffer(p[packet.HeaderLen:])
		field := types.MySQLtypes{}

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

		if err := binary.Read(buf, binary.LittleEndian, &field.FieldInfo); err != nil {
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
	m.Emit.Transmission(types.Response{
		Type:    "SQL results",
		Fields:  m.Fields,
		Results: m.Results,
	})
}

func (m *ResponseDecoder) ResetState() {
	m.State = start
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

// func readFixedString(buf *bytes.Buffer, length int) (string, error) {
// 	b := buf.Next(length)
// 	if len(b) < length {
// 		return "", fmt.Errorf("only read %d bytes", len(b))
// 	}
// 	return string(b), nil
// }
