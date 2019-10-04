package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/gorilla/mux"
)

func main() {
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
