package main

import (
	"database/sql"
	"fmt"
	"jwt-course/driver"
	"log"
	"net/http"

	"github.com/subosito/gotenv"

	"github.com/gorilla/mux"
)

//global db object
var db *sql.DB

func init() {
	gotenv.Load()
}

func main() {

	db = driver.ConnectDB()

	//new router object
	router := mux.NewRouter()

	router.HandleFunc("/signup", signup).Methods("POST")
	router.HandleFunc("/login", login).Methods("POST")
	router.HandleFunc("/protected", TokenVerifyMiddleWare(protectedEndPoint)).Methods("GET")

	fmt.Println("Listen on port 8000...")
	log.Fatal(http.ListenAndServe(":8000", router))

}
