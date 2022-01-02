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
var tpl string

// TODO:
// * allow template to be specified.

func main() {
	var displayVersion bool
	var templateFile string
	pflag.BoolVar(&displayVersion, "version", false, "Display program version")
	pflag.StringVar(&templateFile, "template", "", "Template to summarise with")
	pflag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage %s [files]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\nWith no files reads stdin.\n")
		pflag.PrintDefaults()
	}

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

	templateContents := tpl
	if templateFile != "" {
		b, err := os.ReadFile(templateFile)
		if err != nil {
			log.Fatal(err)
		}
		templateContents = string(b)
	}
	tmpl, err := setupTemplate(templateContents)
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

func setupTemplate(templateContents string) (*template.Template, error) {
	tmpl, err := template.New("text").Funcs(template.FuncMap{
		"val": func(v interface{}) string {
			if v == nil {
				return "null"
			}
			// then switch through the types, kinda like a sprintf but a little
			// more tweaked for SQL
			return fmt.Sprintf("%#v", v)
		},
	}).Parse(templateContents)

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
	d := json.NewDecoder(rdr)
	d.UseNumber()
	t, err := d.Token()
	if err == io.EOF {
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to start reading ports json: %w", err)
	}
	// expecting delim to start
	if d, ok := t.(json.Delim); !ok || d.String() != "[" {
		//nolint:goerr113
		return fmt.Errorf("unexpected start to the json")
	}

	for d.More() {
		v := map[string]interface{}{}
		if err := d.Decode(&v); err != nil {
			return fmt.Errorf("decode failure %w", err)
		}
		if err := tmpl.Execute(output, v); err != nil {
			return err
		}
	}

	return nil
}
