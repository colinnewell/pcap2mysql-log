package main

import "fmt"

func main() {
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

	if len(files) > 0 {
		processFiles(files)
		return
	}

	fmt.Println("Specify pcap2mysql-log files to process")
}

func processFiles(files []string) {
	// load in the json
	// collate it
	// output it
}
