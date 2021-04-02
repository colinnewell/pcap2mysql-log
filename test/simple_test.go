// +build capturetest

package main

import (
	"database/sql"
	"testing"

	_ "github.com/go-sql-driver/mysql"
)

func TestSimpleConnection(t *testing.T) {
	//nolint:lll
	db, err := sql.Open("mysql", "site:84aaa213dbb7aa3d67d57ba49acc2a71b7c4cd8bf689bfdf4372e4a34dceeca0@tcp(localhost:3306)/demo")
	if err != nil {
		t.Fatal(err)
	}

	defer db.Close()

	insert, err := db.Query("INSERT INTO test VALUES ( 2, 'TEST' )")
	if err != nil {
		t.Fatal(err)
	}
	defer insert.Close()
}
