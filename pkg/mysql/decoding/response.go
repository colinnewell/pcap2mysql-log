package decoding

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/colinnewell/pcap2mysql-log/pkg/mysql/decoding/bitmap"
	"github.com/colinnewell/pcap2mysql-log/pkg/mysql/packet"
	"github.com/colinnewell/pcap2mysql-log/pkg/mysql/structure"
	"github.com/pkg/errors"
)

var errUnexpectedValue = errors.New("unexpected value")

type readState byte

const (
	start readState = iota
	fieldInfo
	fieldInfoColumns
	fieldInfoParams
	data

	encodedNull         = 0xfb
	encodedInNext2Bytes = 0xfc
	encodedInNext3Bytes = 0xfd
	encodedInNext8Bytes = 0xfe
)

// ResponseDecoder - dealing with the response.
type ResponseDecoder struct {
	Emit Emitter

	Fields    []structure.ColumnInfo
	State     readState
	Results   [][]interface{}
	prepareOK structure.PrepareOKResponse
}

func (m *ResponseDecoder) String() string {
	return fmt.Sprintf(
		"ResponseDecoder{\n\tFields: %v\n\tState: %v\n\tResults: %v\n\tprepareOK: %v\n}",
		m.Fields,
		m.State,
		m.Results,
		m.prepareOK,
	)
}

//nolint:funlen,gocognit
func (m *ResponseDecoder) Write(p []byte) (int, error) {
	// FIXME: check how much data we have
	switch m.State {
	case start:
		packetType := structure.ResponseType(p[packet.HeaderLen])
		builder := m.Emit.ConnectionBuilder()
		if (!builder.Compressed()) && p[packet.PacketNo] == 0 &&
			packetType != structure.MySQLError {
			err := m.decodeGreeting(p[packet.HeaderLen:])
			if err != nil {
				return 0, errors.Wrap(err, fmt.Sprintf("response-write %v", builder.Compressed()))
			}
			break
		}
		switch packetType {
		case structure.MySQLError:
			m.decodeError(p)
		case structure.MySQLEOF:
			// check if it's really an EOF
			m.Emit.Transmission("EOF", structure.Response{Type: "EOF"})
		case structure.MySQLOK:
			err := m.decodeOK(p[packet.HeaderLen+1:])
			if err != nil {
				return 0, errors.Wrap(err, "response-write")
			}
		case structure.MySQLLocalInfile:
			// check if it's really an EOF
			m.Emit.Transmission("In file", structure.Response{Type: "In file"})
		default:
			m.State = fieldInfo
			m.Fields = []structure.ColumnInfo{}
			m.Results = [][]interface{}{}
		}
	case data:
		if structure.ResponseType(p[packet.HeaderLen]) == structure.MySQLEOF {
			m.FlushResponse()
			m.ResetState()
			break
		}

		b := bytes.NewBuffer(p[packet.HeaderLen:])

		if m.Emit.ConnectionBuilder().PreviousRequestType() == "Execute" {
			if err := m.DecodeBinaryResult(b); err != nil {
				return 0, errors.Wrap(err, "response-write execute data (binary)")
			}
			break
		}

		// FIXME: should I just check if first byte is 0?
		r := make([]interface{}, len(m.Fields))

		for i := range r {
			var err error

			r[i], err = readLenEncString(b)

			if err != nil {
				return 0, errors.Wrap(
					err,
					fmt.Sprintf("response-write data field (string) %d", i),
				)
			}
		}
		m.Results = append(m.Results, r)

	case fieldInfo, fieldInfoColumns, fieldInfoParams:
		if structure.ResponseType(p[packet.HeaderLen]) == structure.MySQLEOF {
			switch {
			case m.State == fieldInfo:
				m.State = data
			case m.State == fieldInfoParams && m.prepareOK.NumColumns > 0:
				m.State = fieldInfoColumns
			default:
				m.Emit.Transmission("PREPARE_OK", m.prepareOK)
				m.ResetState()
			}
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
				return 0, errors.Wrap(err, "response-write fieldinfo")
			}

			*val = s
		}

		if err := binary.Read(buf, binary.LittleEndian, &field.TypeInfo); err != nil {
			return 0, errors.Wrap(err, "response-write")
		}

		switch m.State {
		case fieldInfoColumns:
			m.prepareOK.Columns = append(m.prepareOK.Columns, field)
		case fieldInfoParams:
			m.prepareOK.Params = append(m.prepareOK.Params, field)
		case fieldInfo:
			m.Fields = append(m.Fields, field)
		}
	}

	return len(p), nil
}

func (m *ResponseDecoder) DecodeBinaryResult(b *bytes.Buffer) error {
	h, err := b.ReadByte()
	if err != nil {
		return errors.Wrap(err, "decode-binary-result")
	}
	if h != 0 {
		return errors.Wrap(errUnexpectedValue, "decode-binary-result")
	}

	// null bitmap
	nullMap, err := bitmap.ReadNullMap(b, len(m.Fields), bitmap.ResultSetRow)
	if err != nil {
		return err
	}
	r := make([]interface{}, len(m.Fields))
	for i, col := range m.Fields {
		if nullMap.IsNull(i) {
			r[i] = nil
		} else {
			val, err := readType(
				b, col.TypeInfo.FieldTypes,
				col.TypeInfo.FieldDetail&structure.DETAIL_UNSIGNED != 0,
			)
			if err != nil {
				return errors.Wrap(err, fmt.Sprintf(
					"decode-binary-result: field(%s.%s %s) nullmap %#v",
					col.TableAlias,
					col.ColumnAlias,
					col.TypeInfo.FieldTypes,
					nullMap,
				))
			}
			r[i] = val
		}
	}
	m.Results = append(m.Results, r)
	return nil
}

func (m *ResponseDecoder) FlushResponse() {
	if m.State == start {
		// nothing banked up.
		return
	}
	// flush out all the data we have stored up.
	m.Emit.Transmission("SQL results", structure.ResultSetResponse{
		Type:    "SQL results",
		Columns: m.Fields,
		Results: m.Results,
	})
}

func (m *ResponseDecoder) ResetState() {
	m.State = start
	m.prepareOK = structure.PrepareOKResponse{}
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
	m.Emit.Transmission(errorMsg.Type, errorMsg)
}

func (m *ResponseDecoder) decodeGreeting(p []byte) error {
	protocol := p[0]
	b := bytes.NewBuffer(p[1:])
	version, err := readNulString(b)
	if err != nil {
		return errors.Wrap(err, "decode-greeting")
	}

	// not really interested in all the data here right now.
	// skipping connection id + various other bits.
	//nolint:gomnd
	b.Next(9 + 4)
	capabilityBytes := [4]byte{}
	if n, err := b.Read(capabilityBytes[0:2]); err != nil || n < 2 {
		if err != nil {
			return errors.Wrap(err, "decode-greeting")
		}
		return errors.Wrap(
			errRequestTooFewBytes,
			fmt.Sprintf("decodeGreeting capabilityBytes only read %d bytes", b.Len()),
		)
	}
	collation, err := b.ReadByte()
	if err != nil {
		return errors.Wrap(err, "decode-greeting")
	}
	if n, err := b.Read(capabilityBytes[2:4]); err != nil || n < 2 {
		if err != nil {
			return errors.Wrap(err, "decode-greeting")
		}
		return errors.Wrap(
			errRequestTooFewBytes,
			fmt.Sprintf("decodeGreeting capabilityBytes part 2 only read %d bytes", b.Len()),
		)
	}
	// FIXME: not sure if this is the best way to decode the capability info
	capabilities := binary.LittleEndian.Uint32(capabilityBytes[:])
	m.Emit.Transmission("Greeting", structure.Greeting{
		Capabilities: structure.ClientCapabilities(capabilities),
		Collation:    collation,
		Protocol:     protocol,
		Type:         "Greeting",
		Version:      version,
	})
	return nil
}

func (m *ResponseDecoder) decodeOK(p []byte) error {
	if m.Emit.ConnectionBuilder().PreviousRequestType() == "Prepare" {
		return m.decodePrepareOK(p)
	}
	ok := structure.OKResponse{
		Type: "OK",
	}
	b := bytes.NewBuffer(p)
	for _, val := range []*uint64{&ok.AffectedRows, &ok.LastInsertID} {
		v, err := readLenEncInt(b)
		if err != nil {
			return errors.Wrap(err, "decode-ok")
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
			return errors.Wrap(err, "decode-ok")
		}
	}
	ok.ServerStatus = structure.StatusFlags(serverStatus)
	m.Emit.Transmission(ok.Type, ok)
	return nil
}

func (m *ResponseDecoder) decodePrepareOK(p []byte) error {
	buf := bytes.NewBuffer(p)

	b := struct {
		StatementID uint32
		NumColumns  uint16
		NumParams   uint16
		Unused      byte
		Warnings    int16
	}{}
	if err := binary.Read(buf, binary.LittleEndian, &b); err != nil {
		return errors.Wrap(err, "decode-prepare-ok")
	}

	ok := structure.PrepareOKResponse{
		Type:        "PREPARE_OK",
		StatementID: b.StatementID,
		NumColumns:  b.NumColumns,
		NumParams:   b.NumParams,
		Warnings:    b.Warnings,
	}
	switch {
	case b.NumParams > 0:
		m.State = fieldInfoParams
		m.prepareOK = ok
	case b.NumColumns > 0:
		m.State = fieldInfoColumns
		m.prepareOK = ok
	default:
		m.Emit.Transmission("PREPARE_OK", ok)
	}

	return nil
}
