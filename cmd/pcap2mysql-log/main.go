package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"runtime/debug"

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

	interpreter := decoding.MySQLRequest{}

	if _, err := packet.Copy(m.Request, &interpreter); err != nil {
		log.Println(err)
	}

	fmt.Println("---- From")

	response := decoding.MySQLresponse{}

	if _, err := packet.Copy(m.Response, &response); err != nil {
		return err
	}

	return nil
}
