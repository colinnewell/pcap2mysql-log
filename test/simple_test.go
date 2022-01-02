//go:build capturetest
// +build capturetest

package main

import (
	"database/sql"
	"fmt"
	"strings"
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

func TestInsertAndSelect(t *testing.T) {
	db := connection(t)
	defer db.Close()

	insert, err := db.Prepare("INSERT INTO peeps (name, age) VALUES ( ?, ? )")
	if err != nil {
		t.Fatal(err)
	}
	defer insert.Close()
	insert.Exec("person2", 33)
	insert.Exec("person3", 34)
	insert.Exec("person4", nil)
	stmt, err := db.Prepare("SELECT * FROM peeps WHERE age = ?")
	if err != nil {
		t.Fatal(err)
	}
	defer stmt.Close()
	stmt.Exec(33)
}

func TestLargeTable(t *testing.T) {
	db := connection(t)
	defer db.Close()

	insert, err := db.Prepare(`
	INSERT INTO demo.lots
		(Neque_tempore_est_expedita_omn,
		 Enim_rem_consequuntur_ipsum_na,
		 Similique_et_molestias_modi_si,
		 Eligendi_sed_placeat_nihil_vol,
		 Voluptatum_possimus_sint_venia,
		 Incidunt_deleniti_sunt_ea_reru,
		 Labore_distinctio_cum_vero_mol,
		 Aut_suscipit_nihil_voluptatum_,
		 Corporis_et_facere_voluptatem,
		 Minus_sunt_ut_repudiandae,
		 Sed_dolor_est_reprehenderit_a_)
	VALUES ( ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ? )`)
	if err != nil {
		t.Fatal(err)
	}
	defer insert.Close()
	insert.Exec("person2", 1, 2, 3, 4, "foo", "blah", "booo", "dskaods", "mdsamdskm", 4)
	insert.Exec("person3", 1, 2, 3, 4, nil, "oo", "a", "b", "c", 5)
	var sb strings.Builder
	for i := 0; i < 1500; i++ {
		sb.WriteString(fmt.Sprintf("this is another long line of text line %d\n", i))
	}

	insert.Exec(
		"foo",
		1, 2, 3, 4,
		"ksmlkmdsalmdlsamdlmsamdskmad lksmsakdma slkmd lsamdkmals da",
		"mdksamkdsmd msakdmskam dsa",
		sb.String(),
		sb.String(),
		sb.String(),
		6,
	)

	stmt, err := db.Prepare("SELECT * FROM demo.lots")
	if err != nil {
		t.Fatal(err)
	}
	defer stmt.Close()
	rows, err := stmt.Query()
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		v := [101]interface{}{}
		err := rows.Scan(
			&v[0],
			&v[1],
			&v[2],
			&v[3],
			&v[4],
			&v[5],
			&v[6],
			&v[7],
			&v[8],
			&v[9],
			&v[10],
			&v[11],
			&v[12],
			&v[13],
			&v[14],
			&v[15],
			&v[16],
			&v[17],
			&v[18],
			&v[19],
			&v[20],
			&v[21],
			&v[22],
			&v[23],
			&v[24],
			&v[25],
			&v[26],
			&v[27],
			&v[28],
			&v[29],
			&v[30],
			&v[31],
			&v[32],
			&v[33],
			&v[34],
			&v[35],
			&v[36],
			&v[37],
			&v[38],
			&v[39],
			&v[40],
			&v[41],
			&v[42],
			&v[43],
			&v[44],
			&v[45],
			&v[46],
			&v[47],
			&v[48],
			&v[49],
			&v[50],
			&v[51],
			&v[52],
			&v[53],
			&v[54],
			&v[55],
			&v[56],
			&v[57],
			&v[58],
			&v[59],
			&v[60],
			&v[61],
			&v[62],
			&v[63],
			&v[64],
			&v[65],
			&v[66],
			&v[67],
			&v[68],
			&v[69],
			&v[70],
			&v[71],
			&v[72],
			&v[73],
			&v[74],
			&v[75],
			&v[76],
			&v[77],
			&v[78],
			&v[79],
			&v[80],
			&v[81],
			&v[82],
			&v[83],
			&v[84],
			&v[85],
			&v[86],
			&v[87],
			&v[88],
			&v[89],
			&v[90],
			&v[91],
			&v[92],
			&v[93],
			&v[94],
			&v[95],
			&v[96],
			&v[97],
			&v[98],
			&v[99],
			&v[100],
		)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%#v\n", v)
	}
	err = rows.Err()
	if err != nil {
		t.Fatal(err)
	}
}

func TestNumericTypes(t *testing.T) {
	db := connection(t)
	defer db.Close()

	insert, err := db.Prepare(`
	INSERT INTO demo.dbtypes
		(tiny, med, small, basic, big, utiny, umed, usmall, ubasic, ubig, salary, floater, doubled, bits)
	VALUES
		(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		t.Fatal(err)
	}
	defer insert.Close()
	insert.Exec(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 3.4567, 3.33, 4.44, 3)
	insert.Exec(
		127,
		8388607,
		32767,
		2147483647,
		9223372036854775807,

		255,
		16777215,
		65535,                        // usmall
		4294967295,                   // ubasic
		uint64(18446744073709551615), // ubig
		3.4567, 3.33, 4.44, 3,
	)
	insert.Exec(-1, -2, -3, -4, -5, 6, 7, 8, 9, 10, 3.4567, 3.33, 4.44, 3)
	// FIXME: insert some maximums

	stmt, err := db.Prepare("SELECT * FROM demo.dbtypes")
	if err != nil {
		t.Fatal(err)
	}
	defer stmt.Close()
	rows, err := stmt.Query()
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		v := [15]interface{}{}
		err := rows.Scan(
			&v[0],
			&v[1],
			&v[2],
			&v[3],
			&v[4],
			&v[5],
			&v[6],
			&v[7],
			&v[8],
			&v[9],
			&v[10],
			&v[11],
			&v[12],
			&v[13],
			&v[14],
		)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%#v\n", v)
	}
	err = rows.Err()
	if err != nil {
		t.Fatal(err)
	}
}

func TestDateTypes(t *testing.T) {
	db := connection(t)
	defer db.Close()

	insert, err := db.Prepare(`
	INSERT INTO demo.dates
		(created, start, endYear, y2k)
	VALUES
		(?, ?, ?, ?)
	`)
	if err != nil {
		t.Fatal(err)
	}
	defer insert.Close()
	insert.Exec("2013-03-04", "20:33", "2021", "97")

	stmt, err := db.Prepare("SELECT * FROM demo.dates")
	if err != nil {
		t.Fatal(err)
	}
	defer stmt.Close()
	rows, err := stmt.Query()
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		v := [6]interface{}{}
		err := rows.Scan(
			&v[0],
			&v[1],
			&v[2],
			&v[3],
			&v[4],
			&v[5],
		)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%#v\n", v)
	}
	err = rows.Err()
	if err != nil {
		t.Fatal(err)
	}
}
