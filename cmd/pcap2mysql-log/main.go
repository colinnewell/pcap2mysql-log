package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"runtime/debug"

	"github.com/orderbynull/lottip/protocol"
	"github.com/spf13/pflag"

	"github.com/colinnewell/pcap2mysql-log/internal/mysql/decoding"
	"github.com/colinnewell/pcap2mysql-log/internal/mysql/packet"
)

// MySQLConnection is for reading the two sides of the connection.
type MySQLConnection struct {
	Request  io.Reader
	Response io.Reader
}

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

	c := MySQLConnection{}

	f, err := os.Open(to)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	c.Request = f

	t, err := os.Open(from)
	if err != nil {
		log.Fatal(err)
	}
	defer t.Close()

	c.Response = t

	if err := c.Read(); err != nil {
		log.Fatal(err)
	}
}

func (m *MySQLConnection) Read() error {
	fmt.Println("---- To")

	interpreter := mySQLinterpreter{}

	if _, err := packet.Copy(m.Request, &interpreter); err != nil {
		return err
	}

	fmt.Println("---- From")

	response := decoding.MySQLresponse{}

	if _, err := packet.Copy(m.Response, &response); err != nil {
		return err
	}

	return nil
}

//Build response
//Fields
// Detect the fields & what the types are
// Read the data
//Build request

type mySQLinterpreter struct {
}

func (m *mySQLinterpreter) Write(p []byte) (int, error) {
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

// func
// Parser
//go io.Copy(io.MultiWriter(server, &RequestPacketParser{connId, &queryId, p.cmdChan, p.connStateChan, &timer}), client)

// Copy bytes from server to client and responseParser
//io.Copy(io.MultiWriter(client, &ResponsePacketParser{connId, &queryId, p.cmdResultChan, &timer}), server)
//}
// go get github.com/orderbynull/lottip
