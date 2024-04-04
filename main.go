package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"

	_ "github.com/go-sql-driver/mysql"
	"github.com/kaustubha-chaturvedi/countries-states-and-cities-api/app"
)

var (
	dbUser     = app.Env("DB_USER", "user")
	dbPassword = app.Env("DB_PASSWORD", "password")
	dbName     = app.Env("DB_NAME", "countries_db")
	dbHost     = app.Env("DB_HOST", "localhost")
	dbPort     = app.Env("DB_PORT", "3306")
)

func index(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "Welcome to the Countries, States, and Cities API")
}

func main() {
	var err error
	app.DB, err = sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", dbUser, dbPassword, dbHost, dbPort, dbName))
	if err != nil {
		log.Fatal("Error connecting to database: ", err)
	}
	defer app.DB.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /", index)
	mux.HandleFunc("POST /api/signup", app.Signup)
	mux.HandleFunc("POST /api/login", app.Login)
	mux.HandleFunc("GET /api/locations", app.ListCountries)
	mux.HandleFunc("GET /api/locations/{country}", app.ListStates)
	mux.HandleFunc("GET /api/locations/{country}/{state}", app.ListCities)
	fmt.Println("Server is running")
	log.Fatal(func() error {
		server := &http.Server{Addr: ":8080", Handler: http.Handler(mux)}
		return server.ListenAndServe()
	}())
}
