package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"runtime/debug"
	"text/template"

	"github.com/spf13/pflag"
)

//go:embed text.tmpl
//nolint:gochecknoglobals
var tpl string
var displayVersion bool

// TODO:
// * allow template to be specified.
// * provide help/version info

func main() {
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

	tmpl, err := setupTemplate()
	if err != nil {
		log.Fatal(err)
	}

	if len(files) > 0 {
		processFiles(tmpl, files)
		return
	}

	if err := processTemplate(os.Stdin, os.Stdout, tmpl); err != nil {
		log.Fatal(err)
	}
}

func setupTemplate() (*template.Template, error) {
	tmpl, err := template.New("text").Funcs(template.FuncMap{
		"val": func(v interface{}) string {
			if v == nil {
				return "null"
			}
			// then switch through the types, kinda like a sprintf but a little
			// more tweaked for SQL
			return fmt.Sprintf("%#v", v)
		},
	}).Parse(tpl)

	return tmpl, err
}

func processFiles(tmpl *template.Template, files []string) {
	for _, file := range files {
		rdr, err := os.Open(file)
		if err != nil {
			log.Printf("Failed to read %s: %s", file, err)
			continue
		}
		defer rdr.Close()
		if err := processTemplate(rdr, os.Stdout, tmpl); err != nil {
			log.Printf("Failed to process %s: %s", file, err)
			continue
		}
	}
}

func processTemplate(rdr io.Reader, output io.Writer, tmpl *template.Template) error {
	v := []map[string]interface{}{}
	d := json.NewDecoder(rdr)
	d.UseNumber()
	if err := d.Decode(&v); err != nil {
		return fmt.Errorf("decode failure %w", err)
	}
	return tmpl.Execute(output, v)
}
