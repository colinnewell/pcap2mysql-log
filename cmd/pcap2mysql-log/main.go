package main

import (
	"fmt"
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

	f, err := os.Open(to)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	mysql := mySQLinterpretter{}
	packet.Copy(f, &mysql)
}

type mySQLinterpretter struct {
}

func (m *mySQLinterpretter) Write(p []byte) (int, error) {
	switch protocol.GetPacketType(p) {
	case protocol.ComStmtPrepare:
	case protocol.ComQuery:
		decoded, err := protocol.DecodeQueryRequest(p)
		fmt.Printf("%#v: %v\n", decoded, err)
		fmt.Println(decoded.Query)
	case protocol.ComQuit:
		fmt.Println("quit")
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
