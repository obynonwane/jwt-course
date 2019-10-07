package utils

import (
	"encoding/json"
	"jwt-course/models"
	"net/http"
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
	return
}

//Utility function that sends data back in json
func ResponseJSON(w http.ResponseWriter, data interface{}) {
	json.NewEncoder(w).Encode(data)
}
