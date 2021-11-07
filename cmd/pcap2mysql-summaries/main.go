package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"text/template"

	"github.com/spf13/pflag"
)

//go:embed text.tmpl
var tpl string

// TODO:
// * allow template to be specified.
// * allow read from stdin

func main() {
	pflag.Parse()
	files := pflag.Args()

	tmpl, err := setupTemplate()
	if err != nil {
		log.Fatal(err)
	}

	if len(files) > 0 {
		processFiles(tmpl, files)
		return
	}

	fmt.Println("Specify pcap2mysql-log files to process")
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
		return fmt.Errorf("decode failure %s", err)
	}
	return tmpl.Execute(output, v)
}
