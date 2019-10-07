package controllers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"jwt-course/models"
	"jwt-course/utils"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
)

//signup handler function
func signup(w http.ResponseWriter, r *http.Request) {
	var user models.User

	json.NewDecoder(r.Body).Decode(&user)

	//validating email input
	if user.Email == "" {

		utils.RespondWithError(w, http.StatusBadRequest, "Email is missing")

		//execution leaves the handler
		return
	}

	//validating password input
	if user.Password == "" {

		utils.RespondWithError(w, http.StatusBadRequest, "Password is missing")

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

		utils.RespondWithError(w, http.StatusInternalServerError, "Server Error.") //responseWriterError is a utility function to  handle error response
		return
	}
	//set password to empty string so it wont be returned
	user.Password = ""

	//set content type to be sent
	w.Header().Set("Content-Type", "application/json")

	//Call utility function for sending back response for user signup passing
	//content type and created user
	utils.ResponseJSON(w, user)

}

//Login Handler Function
func login(w http.ResponseWriter, r *http.Request) {
	//user object
	var user models.User // from struct
	//var error models.Error //from struct
	var jwt models.JWT //from JWT Struct

	//decode the user object received from input and map  to the user struct/user varaiable
	json.NewDecoder(r.Body).Decode(&user)

	//returned error if no email is sent
	if user.Email == "" {
		utils.RespondWithError(w, http.StatusBadRequest, "Email is Missing")
		return
	}

	//returned error if no password is submitted
	if user.Password == "" {
		utils.RespondWithError(w, http.StatusBadRequest, "Password is Missing")
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
			utils.RespondWithError(w, http.StatusBadRequest, "The user does not Exists")
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

		utils.RespondWithError(w, http.StatusBadRequest, "Invalid Password Supplied")

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
	utils.ResponseJSON(w, jwt) //Return jwt and response status to the client

}

//It validates the token we send from the client to the server
//and it gives us access to the protected end point
func TokenVerifyMiddleWare(next http.HandlerFunc) http.HandlerFunc {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		//handling Error from the Error Type
		var errorObject models.Error

		//this variable holds the value of authorization header
		//we send from the client to the server
		//authHeader - is a request object containing a field called Header
		//Header is a map of key vale pair of Key-Authorization, Value- jwt token
		authHeader := r.Header.Get("Authorization")
		//the string method splits the bearer and the token make them individual elements - Array of Two Elements
		bearerToken := strings.Split(authHeader, " ")

		//pick the second element which is the token - ie extract the token
		if len(bearerToken) == 2 {
			authToken := bearerToken[1]

			//validates a token from the client using the Parse method and retuns the token/key
			token, error := jwt.Parse(authToken, func(token *jwt.Token) (interface{}, error) {
				//validating algorithm used
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("There was an error")
				}
				//return the secret as stream of byte
				return []byte(os.Getenv("SECRET")), nil

			})

			//message if there is an error during token validation
			if error != nil {
				errorObject.Message = error.Error()
				utils.RespondWithError(w, http.StatusUnauthorized, "Error")
				return
			}

			//checking if the token is valid or not valid
			if token.Valid {
				//invoking the next function that is been called
				next.ServeHTTP(w, r)
			} else {
				errorObject.Message = error.Error()
				utils.RespondWithError(w, http.StatusUnauthorized, "Error")
				return
			}
		} else {
			utils.RespondWithError(w, http.StatusUnauthorized, "Error")
			return
		}
	})
}