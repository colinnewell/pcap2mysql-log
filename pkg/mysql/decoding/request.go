package decoding

import (
	"bytes"
	"encoding/binary"

	"github.com/colinnewell/pcap2mysql-log/pkg/mysql/packet"
	"github.com/colinnewell/pcap2mysql-log/pkg/mysql/structure"
)

type RequestDecoder struct {
	Emit Emitter
}

func (m *RequestDecoder) Write(p []byte) (int, error) {
	// FIXME: check we have enough bytes
	switch t := CommandCode(p[packet.HeaderLen]); t {
	case reqStmtPrepare:
		query := p[packet.HeaderLen+1:]
		m.Emit.Transmission("Prepare", structure.Request{Type: "Prepare", Query: string(query)})
	case reqQuery:
		query := p[packet.HeaderLen+1:]
		m.Emit.Transmission("Query", structure.Request{Type: "Query", Query: string(query)})
	case reqQuit:
		m.Emit.Transmission("QUIT", structure.Request{Type: "QUIT"})
	case reqStmtExecute:
		return m.decodeExecute(p)
	default:
		if p[packet.PacketNo] == 1 {
			return m.decodeLoginPacket(p)
		}
		m.Emit.Transmission(t.String(), structure.Request{Type: t.String()})
	}
	return len(p), nil
}

func (m *RequestDecoder) decodeLoginPacket(p []byte) (int, error) {
	login := structure.LoginRequest{Type: "Login"}
	b := bytes.NewBuffer(p[packet.HeaderLen:])
	v := struct {
		ClientCapabilities   uint32
		MaxPacketSize        uint32
		Collation            byte
		Reserved             [19]byte
		ExtendedCapabilities uint32
	}{}
	if err := binary.Read(b, binary.LittleEndian, &v); err != nil {
		return 0, err
	}
	login.ClientCapabilities = v.ClientCapabilities
	login.Collation = v.Collation
	login.ExtendedCapabilities = v.ExtendedCapabilities
	login.MaxPacketSize = v.MaxPacketSize

	username, err := readNulString(b)
	if err != nil {
		return 0, err
	}

	login.Username = username

	m.Emit.Transmission(login.Type, login)

	return len(p), nil
}

// NOTE: should refactor, just want more code before I figure out exactly where.
//nolint:gocognit
func (m *RequestDecoder) decodeExecute(p []byte) (int, error) {
	buf := bytes.NewBuffer(p[packet.HeaderLen+1:])
	hdr := struct {
		StatementID    uint32
		Flags          uint8
		IterationCount uint32
	}{}
	if err := binary.Read(buf, binary.LittleEndian, &hdr); err != nil {
		return 0, err
	}
	er := structure.ExecuteRequest{
		Type:           "Execute",
		StatementID:    hdr.StatementID,
		Flags:          hdr.Flags,
		IterationCount: hdr.IterationCount,
	}

	//nolint:nestif
	if buf.Len() > 1 {
		for paramCount := 0; buf.Len() > 0; paramCount++ {
			if paramCount%8 == 0 {
				var nullBitmap uint8
				if err := binary.Read(buf, binary.LittleEndian, &nullBitmap); err != nil {
					return 0, err
				}
				er.NullMap = append(er.NullMap, nullBitmap)
			}
			var send uint8
			if err := binary.Read(buf, binary.LittleEndian, &send); err != nil {
				return 0, err
			}
			if send == 1 {
				a := struct {
					FieldType structure.FieldType
					ParamFlag byte
				}{}

				if err := binary.Read(buf, binary.LittleEndian, &a); err != nil {
					return 0, err
				}

				switch a.FieldType {
				case structure.FLOAT:
				case structure.DOUBLE:
				case structure.LONGLONG:
				case structure.INT24:

				case structure.SHORT,
					structure.YEAR:

				case structure.TINY:

				case structure.DATE,
					structure.DATETIME,
					structure.TIMESTAMP:

				case structure.TIME:

				case structure.STRING,
					structure.VAR_STRING,
					structure.VARCHAR:

					data, err := readLenEncBytes(buf)
					if err != nil {
						return 0, err
					}
					er.Params = append(er.Params, string(data))

				default:
					data, err := readLenEncBytes(buf)
					if err != nil {
						return 0, err
					}
					er.Params = append(er.Params, data)
					// FIXME: if this is a string, let's turn it into a
					// string so it comes out nicely.
					// byte<lenenc> encoding
					// starts with length encoded int for length,
					// then we have the bytes
				}
			} else {
				// FIXME: should check if this means null
				er.Params = append(er.Params, nil)
			}
		}
	}
	m.Emit.Transmission(er.Type, er)

	return len(p), nil
}
