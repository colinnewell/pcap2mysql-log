package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"os"
	"runtime/debug"

	"github.com/orderbynull/lottip/protocol"
	"github.com/spf13/pflag"

	"github.com/colinnewell/pcap2mysql-log/internal/mysql/packet"
)

func main() {
	var displayVersion bool
	var to, from string

	pflag.BoolVar(&displayVersion, "version", false, "Display program version")
	pflag.StringVar(&to, "to", "", "Traffic to the mysql server")
	pflag.StringVar(&from, "from", "", "Traffic from the mysql server")
	pflag.Parse()

	buildVersion := "unknown"
	if bi, ok := debug.ReadBuildInfo(); ok {
		// NOTE: right now this probably always returns (devel).  Hopefully
		// will improve with new versions of Go.  It might be neat to add
		// dep info too at some point since that's part of the build info.
		buildVersion = bi.Main.Version
	}

	if displayVersion {
		fmt.Printf("Version: %s %s\n", Version, buildVersion)
		return
	}

	// FIXME: check to and from are specified
	if to == "" || from == "" {
		log.Fatal("Must specify --to and --from files with traffic")
	}

	fmt.Println("---- To")
	dumpFile(to, &mySQLinterpretter{})
	fmt.Println("---- From")
	dumpFile(from, &mySQLresponse{})
}

func dumpFile(filename string, mysql io.Writer) {
	f, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	packet.Copy(f, mysql)
}

//Build response
//Fields
// Detect the fields & what the types are
// Read the data
//Build request

type mySQLinterpretter struct {
}

type mySQLtypes struct {
	Catalog     string
	TableAlias  string
	Table       string
	Schema      string
	Column      string
	ColumnAlias string
	FieldInfo   mySQLfieldinfo
}

type mySQLfieldinfo struct {
	LengthOfFixesFields byte
	CharacterSetNumber  uint16
	MaxColumnSize       uint32
	FieldTypes          byte
	FieldDetail         uint16
	Decimals            byte
	Unused              uint16
}

type mySQLresponse struct {
	Fields     []mySQLtypes
	InResponse bool
	EOFCount   int
}

func (m *mySQLresponse) Write(p []byte) (int, error) {
	if m.InResponse {
		switch t := protocol.GetPacketType(p); t {
		case protocol.ResponseErr:
			decoded, err := protocol.DecodeErrResponse(p)
			fmt.Printf("%#v: %v\n", decoded, err)
		case protocol.ResponseOk:
			decoded, err := protocol.DecodeOkResponse(p)
			fmt.Printf("%#v: %v\n", decoded, err)
		case 1:
			//assuming this is the data
			fmt.Println("Response Data")
			fmt.Printf("%#v\n", p)
		case 3:
			fmt.Println("Field definition")
			buf := bytes.NewBuffer(p[4:])
			field := mySQLtypes{}

			for _, val := range []*string{
				&field.Catalog,
				&field.Schema,
				&field.TableAlias,
				&field.Table,
				&field.ColumnAlias,
				&field.Column,
			} {
				s, err := readString(buf)

				if err != nil {
					return 0, err
				}

				*val = s
			}

			if err := binary.Read(buf, binary.LittleEndian, &field.FieldInfo); err != nil {
				return 0, err
			}

			m.Fields = append(m.Fields, field)

			fmt.Printf("%#v\n", field)

		case 0xfe:
			fmt.Println("EOF")
			m.EOFCount = m.EOFCount + 1

			if m.EOFCount >= 2 {
				m.InResponse = false
				m.EOFCount = 0
			}
		default:
			fmt.Printf("Unrecognised packet: %x\n", t)
		}
	} else {
		fmt.Printf("Expecting: %d fields\n", p[4])
		m.InResponse = true
	}

	return len(p), nil
}

func (m *mySQLinterpretter) Write(p []byte) (int, error) {
	switch t := protocol.GetPacketType(p); t {
	case protocol.ComStmtPrepare:
		fmt.Println("Prepare")
	case protocol.ComQuery:
		decoded, err := protocol.DecodeQueryRequest(p)
		if err != nil {
			fmt.Printf("%v: %#v\n", err, p)
		} else {
			fmt.Printf("%#v\n", decoded)
		}
	case protocol.ComQuit:
		fmt.Println("quit")
		fmt.Printf("%#v\n", p)
	case protocol.ResponseErr:
		decoded, err := protocol.DecodeErrResponse(p)
		fmt.Printf("%#v: %v\n", decoded, err)
	case protocol.ResponseOk:
		decoded, err := protocol.DecodeOkResponse(p)
		fmt.Printf("%#v: %v\n", decoded, err)
	case 0x04:
		fmt.Println("Field list")
		fmt.Printf("%#v\n", p)
		// should expect a bunch of fields followed by an EOF
		// specifies number of fields to expect
	case 0xfe:
		fmt.Println("EOF")
	default:
		fmt.Printf("Unrecognised packet: %x\n", t)
	}
	return len(p), nil
}

func readString(buf *bytes.Buffer) (string, error) {
	count, err := buf.ReadByte()

	if err != nil {
		return "", err
	}

	s := string(buf.Next(int(count)))

	if len(s) < int(count) {
		return "", fmt.Errorf("Only read %d bytes", len(s))
	}

	return s, nil
}

// func
// Parser
//go io.Copy(io.MultiWriter(server, &RequestPacketParser{connId, &queryId, p.cmdChan, p.connStateChan, &timer}), client)

// Copy bytes from server to client and responseParser
//io.Copy(io.MultiWriter(client, &ResponsePacketParser{connId, &queryId, p.cmdResultChan, &timer}), server)
//}
// go get github.com/orderbynull/lottip
