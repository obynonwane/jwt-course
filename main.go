package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"

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

	//new router object
	router := mux.NewRouter()

	router.HandleFunc("/signup", signup).Methods("POST")
	router.HandleFunc("/login", login).Methods("POST")
	router.HandleFunc("/protected", TokenVerifyMiddleWare(protectedEndPoint)).Methods("GET")

	fmt.Println("Listen on port 8000...")
	log.Fatal(http.ListenAndServe(":8000", router))

}

//Utility function that handle error responses
func respondWithError(w http.ResponseWriter, status int, error Error) {

	//invoking response writer to send status code of 400 - Bad request
	w.WriteHeader(status)

	//pass the custom message back
	json.NewEncoder(w).Encode(error)

	//execution leaves the handler
	return
}

//Utility function that sends data back in json
func responseJSON(w http.ResponseWriter, data interface{}) {
	json.NewEncoder(w).Encode(data)
}

//signup handler function
func signup(w http.ResponseWriter, r *http.Request) {
	var user User
	var error Error

	json.NewDecoder(r.Body).Decode(&user)

	//validating email input
	if user.Email == "" {
		//bad reques
		error.Message = "Email is missing"

		respondWithError(w, http.StatusBadRequest, error)

		//execution leaves the handler
		return
	}

	//validating password input
	if user.Password == "" {
		//bad reques
		error.Message = "Password is missing"

		respondWithError(w, http.StatusBadRequest, error)

		//execution leaves the handler
		return

	}

	//generate password byte stream
	hash, err := bcrypt.GenerateFromPassword([]byte(user.Password), 10)

	if err != nil {
		log.Fatal(err)
	}
	//return the password to string literal acceptable for submission to db
	user.Password = string(hash)

	//query statement
	stmt := "insert into users (email, password) values($1, $2) RETURNING id;"

	//perferm db query submission - perform query execution
	err = db.QueryRow(stmt, user.Email, user.Password).Scan(&user.ID)

	//check if there is error in query execution
	if err != nil {
		error.Message = "Server Error."
		respondWithError(w, http.StatusInternalServerError, error) //responseWriterError is a utility function to  handle error response
		return
	}
	//set password to empty string so it wont be returned
	user.Password = ""

	//set content type to be sent
	w.Header().Set("Content-Type", "application/json")

	//Call utility function for sending back response for user signup passing
	//content type and created user
	responseJSON(w, user)

}

//Utility function to generate toiken for signed In User
func GenerateToken(user User) (string, error) {
	var err error
	secret := "secret"

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": user.Email,
		"iss":   "course",
	})

	//generate signed token using the secrete given
	tokenString, err := token.SignedString([]byte(secret))

	//check if error during token generation
	if err != nil {
		log.Fatal(err)
	}

	//return the token to login
	return tokenString, nil

}

//Login Handler Function
func login(w http.ResponseWriter, r *http.Request) {
	//user object
	var user User   // from struct
	var error Error //from struct
	var jwt JWT     //from JWT Struct

	//decode the user object received from input and map  to the user struct/user varaiable
	json.NewDecoder(r.Body).Decode(&user)

	//returned error if no email is sent
	if user.Email == "" {
		error.Message = "Email is Missing"
		respondWithError(w, http.StatusBadRequest, error)
		return
	}

	//returned error if no password is submitted
	if user.Password == "" {
		error.Message = "Password is Missing"
		respondWithError(w, http.StatusBadRequest, error)
		return
	}
	//get plaintext password
	password := user.Password

	//perform query to select user with given email address
	row := db.QueryRow("select * from users where email = $1", user.Email)

	//scan for error and map the row to respective attributes
	err := row.Scan(&user.ID, &user.Email, &user.Password)

	//check if email or user exist
	if err != nil {
		if err == sql.ErrNoRows {
			error.Message = "The user does not Exists"
			respondWithError(w, http.StatusBadRequest, error)
			return
		} else {
			log.Fatal(err)
		}
	}
	//get hashed password
	hashedPassword := user.Password

	//compare hashed password and plain password - returns nill on success
	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))

	if err != nil {
		error.Message = "Invalid Password Supplied"
		respondWithError(w, http.StatusBadRequest, error)

		return
	}
	//pass the user object to Utility function while returining token and error if any
	//i.e we invoke to GenerateToken func to create the user token and return it
	token, err := GenerateToken(user)

	//check if there is any during token creation
	if err != nil {
		log.Fatal(err)
	}
	//header containing respo
	w.WriteHeader(http.StatusOK)
	jwt.Token = token
	responseJSON(w, jwt) //Return jwt and response status to the client

}

//Handler function for Protected Middleware
func protectedEndPoint(w http.ResponseWriter, r *http.Request) {
	fmt.Println("protectedEndPoint Invoked .....")
}

//It validates the token we send from the client to the server
func TokenVerifyMiddleWare(next http.HandlerFunc) http.HandlerFunc {
	fmt.Println("TokenVerifyMiddleWare Invoked .....")
	return nil
}
