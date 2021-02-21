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

	Fields []types.MySQLtypes
	State  readState
}

func (m *ResponseDecoder) decodeGreeting(p []byte) error {
	protocol := p[0]
	b := bytes.NewBuffer(p[1:])
	version, err := readNulString(b)
	if err != nil {
		return err
	}
	fmt.Printf("Protocol: %d\nVersion: %s\n", protocol, version)

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
	fmt.Printf("Collation: %x\nCapabilities: %b - %x\n", collation, capabilities, capabilities)
	return nil
}

//nolint:funlen
func (m *ResponseDecoder) Write(p []byte) (int, error) {
	// FIXME: check how much data we have
	switch m.State {
	case start:
		if p[packet.PacketNo] == 0 {
			fmt.Printf("Greeting\n%#v\n", p)
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
			fmt.Println("In file")
		default:
			fmt.Printf("Expecting: %d fields\n", p[packet.HeaderLen])
			m.State = fieldInfo
			m.Fields = []types.MySQLtypes{}
		}
	case data:
		if types.ResponseType(p[packet.HeaderLen]) == types.MySQLEOF {
			m.FlushResponse()
			m.State = start
			break
		}

		fmt.Println("Response Data")
		r := make([]string, len(m.Fields))

		b := bytes.NewBuffer(p[packet.HeaderLen:])

		for i := range r {
			var err error

			r[i], err = readLenEncString(b)

			if err != nil {
				return 0, err
			}
		}

		for i, v := range r {
			fmt.Printf("%s(%s.%s): %s\n", m.Fields[i].ColumnAlias, m.Fields[i].Table, m.Fields[i].Column, v)
		}

	case fieldInfo:
		if types.ResponseType(p[packet.HeaderLen]) == types.MySQLEOF {
			m.State = data
			break
		}

		fmt.Println("Field definition")

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

		fmt.Printf("%+v\n", field)
	default:
		// does this case still make sense?
		fmt.Printf("Unrecognised packet: %x\n", p[0])
	}

	return len(p), nil
}

func (m *ResponseDecoder) FlushResponse() {
	m.Emit.Transmission(types.Response{
		Type: "SQL results",
	})
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
