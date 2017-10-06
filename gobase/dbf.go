package gobase

import (
	"fmt"
	// "log"
	"database/sql"
	_ "github.com/lib/pq"
)

func Testpf() {
	fmt.Println("test db connection")
	db, err := sql.Open("postgres", "user=gopher password=gopass dbname=gobasedb sslmode=disable")
	checkErr(err)
	defer db.Close()

	rows, err := db.Query("SELECT id, name FROM public.t_person;")
	checkErr(err)

	fmt.Println("id | name ")
	for rows.Next() {
		var id int
		var name string

		err = rows.Scan(&id, &name)
		checkErr(err)
		
		fmt.Printf("%2v | %4v\n", id, name)
	}
}

func checkErr(err error) {
	if err != nil {
		panic(err)
	}
}
