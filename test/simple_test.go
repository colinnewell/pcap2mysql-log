// +build capturetest

package main

import (
	"database/sql"
	"testing"

	_ "github.com/go-sql-driver/mysql"
)

func TestSimpleConnection(t *testing.T) {
	//nolint:lll
	db, err := sql.Open("mysql", "site:84aaa213dbb7aa3d67d57ba49acc2a71b7c4cd8bf689bfdf4372e4a34dceeca0@tcp(127.0.0.1:3306)/demo")
	if err != nil {
		t.Fatal(err)
	}

	defer db.Close()
}
