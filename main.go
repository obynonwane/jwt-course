package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"

	"github.com/gorilla/mux"
)

//defining our model
type User struct {
	ID       int    `json:"id"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type JWT struct {
	Token string `json:"token"`
}

type Error struct {
	Message string `json:"message"`
}

//global db object
var db *sql.DB

func main() {
	//connection string
	pgUrl, err := pq.ParseURL("postgres://vwbmbsno:M86A301aHWOebuEum0ypW00pTkqAOftz@salt.db.elephantsql.com:5432/vwbmbsno")

	fmt.Println(db)

	//check if there is error in connection
	if err != nil {
		log.Fatal(err)
	}
	//connection credentials
	db, err = sql.Open("Postgres", pgUrl)

	//check if there is error in connection
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(db)

	//new router object
	router := mux.NewRouter()

	router.HandleFunc("/signup", signup).Methods("POST")
	router.HandleFunc("/login", login).Methods("POST")
	router.HandleFunc("/protected", TokenVerifyMiddleWare(protectedEndPoint)).Methods("GET")

	fmt.Println("Listen on port 8000...")
	log.Fatal(http.ListenAndServe(":8000", router))

}

//signup handler function
func signup(w http.ResponseWriter, r *http.Request) {

	w.Write([]byte("Succesfully called Signup"))
}

//Login Handler Function
func login(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Succesfully called Login"))
}

//Handler function for Protected Middleware
func protectedEndPoint(w http.ResponseWriter, r *http.Request) {
	fmt.Println("protectedEndPoint Invoked .....")
}

//Our Middleware Function
func TokenVerifyMiddleWare(next http.HandlerFunc) http.HandlerFunc {
	fmt.Println("TokenVerifyMiddleWare Invoked .....")

	return nil
}
