// +build capturetest

package main

import (
	"database/sql"
	"testing"

	_ "github.com/go-sql-driver/mysql"
)

func connection(t *testing.T) *sql.DB {
	t.Helper()

	//nolint:lll
	db, err := sql.Open("mysql", "site:84aaa213dbb7aa3d67d57ba49acc2a71b7c4cd8bf689bfdf4372e4a34dceeca0@tcp(localhost:3306)/demo")
	if err != nil {
		t.Fatal(err)
	}
	return db
}

func TestSimpleError(t *testing.T) {
	db := connection(t)
	defer db.Close()

	insert, err := db.Query("INSERT INTO test VALUES ( 2, 'TEST' )")
	if err == nil {
		defer insert.Close()
		t.Fatal("Should have raised an error")
	}
}

func TestSimpleInsert(t *testing.T) {
	db := connection(t)
	defer db.Close()

	insert, err := db.Query("INSERT INTO peeps (name, age) VALUES ( ?, ? )", "person", 33)
	if err != nil {
		t.Fatal(err)
	}
	defer insert.Close()
}
