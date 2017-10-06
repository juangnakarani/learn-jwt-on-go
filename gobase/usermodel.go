package gobase

import (
	"fmt"
	// "log"
	"database/sql"

	_ "github.com/lib/pq"
)

type User struct {
	ID       int
	Email    string
	Username string
	Password string
}

func Testpf() {
	fmt.Println("test db connection")
	db, err := sql.Open("postgres", "user=gopher password=gopass dbname=gobasedb sslmode=disable")
	checkErr(err)
	defer db.Close()

	//use COALESCE to handle null data on database level
	rows, err := db.Query("SELECT id, COALESCE(email,'') email, username, password FROM public.t_person;")
	checkErr(err)

	fmt.Println("id | email | username  | password")
	for rows.Next() {
		var id int
		var email string
		var username string
		var password string

		err = rows.Scan(&id, &email, &username, &password)
		checkErr(err)

		fmt.Printf("%2v | %10v | %10v |%2v\n", id, email, username, password)
	}
}
func getConnection() (*sql.DB, error) {
	fmt.Println("getting db connection")
	db, err := sql.Open("postgres", "user=gopher password=gopass dbname=gobasedb sslmode=disable")
	checkErr(err)
	// defer db.Close()
	return db, err
}

func GetUsers() ([]*User, error) {
	fmt.Println("getting username")
	db, err := sql.Open("postgres", "user=gopher password=gopass dbname=gobasedb sslmode=disable")
	checkErr(err)
	defer db.Close()

	var users []*User
	//use COALESCE to handle null data on database level
	rows, err := db.Query("SELECT id, username, password, COALESCE(email,'') as email FROM public.t_person")

	for rows.Next() {
		var user User
		err = rows.Scan(&user.ID, &user.Username, &user.Password, &user.Email)
		checkErr(err)
		users = append(users, &user)
	}
	fmt.Println("return")
	return users, err
}

func Login(username string, password string) (*User, error) {
	db, err := getConnection()
	checkErr(err)

	var user User
	rows, err := db.Query("SELECT id, username, password, email FROM public.t_person WHERE username=$1 AND password=$2", username, password)
	defer rows.Close()
	for rows.Next() {
		err = rows.Scan(&user.ID, &user.Username, &user.Password, &user.Email)
		checkErr(err)
	}
	return &user, err
}

func checkErr(err error) {
	if err != nil {
		panic(err)
	}
}
