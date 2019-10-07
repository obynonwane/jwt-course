package controllers

import (
	"fmt"
	"jwt-course/utils"
	"net/http"
)

//Handler function for Protected Middleware
func protectedEndPoint(w http.ResponseWriter, r *http.Request) {
	fmt.Println("protectedEndPoint Invoked .....")
	utils.ResponseJSON(w, "yes")
}
