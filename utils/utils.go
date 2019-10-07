package utils

import (
	"encoding/json"
	"jwt-course/models"
	"log"
	"net/http"
	"os"

	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
)

//Utility function that handle error responses
func RespondWithError(w http.ResponseWriter, status int, message string) {

	var error models.Error

	error.Message = message

	//invoking response writer to send status code of 400 - Bad request
	w.WriteHeader(status)

	//pass the custom message back
	json.NewEncoder(w).Encode(error)

	//execution leaves the handler
	//return
}

//Utility function that sends data back in json
func ResponseJSON(w http.ResponseWriter, data interface{}) {
	json.NewEncoder(w).Encode(data)
}

func ComparePasswords(hashedPassword string, password []byte) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), password)

	if err != nil {
		log.Println(err)
		return false
	}
	return true
}

//Utility function to generate toiken for signed In User
func GenerateToken(user models.User) (string, error) {
	var err error
	secret := os.Getenv("SECRET") //we used it to sign the jwt token

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": user.Email,
		"iss":   "course",
	})

	//generate signed token using the secrete given
	tokenString, err := token.SignedString([]byte(secret))

	//check if error during signing of token generation
	if err != nil {
		log.Fatal(err)
	}

	//return the token to login - cause it invokdd this func
	return tokenString, nil

}


