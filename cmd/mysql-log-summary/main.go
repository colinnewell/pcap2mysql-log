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

	if displayVersion {
		buildVersion := "unknown"
		if bi, ok := debug.ReadBuildInfo(); ok {
			// NOTE: right now this probably always returns (devel).  Hopefully
			// will improve with new versions of Go.  It might be neat to add
			// dep info too at some point since that's part of the build info.
			buildVersion = bi.Main.Version
		}

		fmt.Printf("Version: %s %s\n", Version, buildVersion)
		return
	}

	files := pflag.Args()
	if len(files) == 0 {
		fmt.Println("Specify capture logs files to process")
		return
	}

	processFiles(files)
}

func processFiles(files []string) {
	for _, filename := range files {
		processFile(filename)
	}
}

func processFile(filename string) {
	// read json
	// iterate and print out info
}
