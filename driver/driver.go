package driver

import (
	"database/sql"
	"log"
	"os"

	"github.com/lib/pq"
)

var db *sql.DB

//this function will return a database instance once a connection is established
func ConnectDB() *sql.DB {

	//connection string
	pgUrl, err := pq.ParseURL(os.Getenv("ELEPHANTSQL_URL"))

	//check if there is error in connection
	if err != nil {
		log.Fatal(err)
	}
	//database handle connection created using the .Open method credentials
	//postgres = db driver
	//pgUrl = specifies database connection credentials
	db, err = sql.Open("postgres", pgUrl)

	//check if there is error in connection
	if err != nil {
		log.Fatal(err)
	}
	//check if a connection to database is established else returns an error if response is empty no error
	err = db.Ping()

	if err != nil {
		log.Fatal(err)
	}

	return db
}
