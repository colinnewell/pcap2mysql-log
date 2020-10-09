package main

import (
	"fmt"
	"runtime/debug"

	"github.com/spf13/pflag"
)

func main() {
	var displayVersion bool

	pflag.BoolVar(&displayVersion, "version", false, "Display program version")
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

}
