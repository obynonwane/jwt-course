package utils

import (
	"encoding/json"
	"fmt"
	"jwt-course/models"
	"log"
	"net/http"
	"os"
	"strings"

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
				RespondWithError(w, http.StatusUnauthorized, "Error")
				return
			}

			//checking if the token is valid or not valid
			if token.Valid {
				//invoking the next function that is been called
				next.ServeHTTP(w, r)
			} else {
				errorObject.Message = error.Error()
				RespondWithError(w, http.StatusUnauthorized, "Error")
				return
			}
		} else {
			RespondWithError(w, http.StatusUnauthorized, "Error")
			return
		}
	})
}
