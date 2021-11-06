package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"text/template"

	"github.com/spf13/pflag"
)

//go:embed text.tmpl
var tpl string

func main() {
	//if displayVersion {
	//	buildVersion := "unknown"
	//	if bi, ok := debug.ReadBuildInfo(); ok {
	//		// NOTE: right now this probably always returns (devel).  Hopefully
	//		// will improve with new versions of Go.  It might be neat to add
	//		// dep info too at some point since that's part of the build info.
	//		buildVersion = bi.Main.Version
	//	}

	//	fmt.Printf("Version: %s %s\n", Version, buildVersion)
	//	return
	//}

	pflag.Parse()
	files := pflag.Args()

	if len(files) > 0 {
		processFiles(files)
		return
	}

	fmt.Println("Specify pcap2mysql-log files to process")
}

func processFiles(files []string) {

	for _, file := range files {

		data, err := os.ReadFile(file)
		if err != nil {
			log.Printf("Failed to read %s: %s", file, err)
			continue
		}
		v := []map[string]interface{}{}
		if err := json.Unmarshal(data, &v); err != nil {
			log.Printf("Failed to decode %s: %s", file, err)
			continue
		}
		// now push through the template engine
		tmpl, err := template.New("text").Parse(tpl)
		if err != nil {
			log.Printf("Failed to process template %s", err)
			continue
		}

		err = tmpl.Execute(os.Stdout, v)
	}
	// load in the json
	// collate it
	// output it
}
