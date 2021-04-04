package decoding

import (
	"bytes"
	"encoding/binary"

	"github.com/colinnewell/pcap2mysql-log/pkg/mysql/packet"
	"github.com/colinnewell/pcap2mysql-log/pkg/mysql/structure"
	"github.com/pkg/errors"
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
		builder := m.Emit.ConnectionBuilder()
		if builder.JustSeenGreeting() ||
			(builder.PreviousRequestType() == "" && p[packet.PacketNo] == 1) {
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
		return 0, errors.Wrap(err, "decode-login-packet")
	}
	login.ClientCapabilities = v.ClientCapabilities
	login.Collation = v.Collation
	login.ExtendedCapabilities = v.ExtendedCapabilities
	login.MaxPacketSize = v.MaxPacketSize

	username, err := readNulString(b)
	if err != nil {
		return 0, errors.Wrap(err, "deocde-login-packet")
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
		return 0, errors.Wrap(err, "decode-execute")
	}
	er := structure.ExecuteRequest{
		Type:           "Execute",
		StatementID:    hdr.StatementID,
		Flags:          hdr.Flags,
		IterationCount: hdr.IterationCount,
	}

	paramCount := m.Emit.ConnectionBuilder().ParamsForQuery(hdr.StatementID)

	//nolint:nestif
	if buf.Len() > 1 && paramCount > 0 {
		nullBitmap := make([]byte, (paramCount+7)/8)
		if _, err := buf.Read(nullBitmap); err != nil {
			return 0, errors.Wrap(err, "failed to read nullmap")
		}
		er.NullMap = nullBitmap
		var send uint8
		if err := binary.Read(buf, binary.LittleEndian, &send); err != nil {
			return 0, errors.Wrap(err, "decode-execute")
		}
		if send == 1 {
			params := make([]struct {
				FieldType structure.FieldType
				ParamFlag byte
			}, paramCount)

			for n := uint16(0); n < paramCount; n++ {
				if err := binary.Read(buf, binary.LittleEndian, &params[n]); err != nil {
					return 0, errors.Wrap(err, "decode-execute")
				}
			}
			for n := uint16(0); n < paramCount; n++ {
				switch params[n].FieldType {
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
						return 0, errors.Wrap(err, "decode-execute")
					}
					er.Params = append(er.Params, string(data))

				default:
					data, err := readLenEncBytes(buf)
					if err != nil {
						return 0, errors.Wrap(err, "decode-execute")
					}
					er.Params = append(er.Params, data)
					// FIXME: if this is a string, let's turn it into a
					// string so it comes out nicely.
					// byte<lenenc> encoding
					// starts with length encoded int for length,
					// then we have the bytes
				}
			}
		}
	}
	m.Emit.Transmission(er.Type, er)

	return len(p), nil
}
