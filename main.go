package main

import (
	"log"
	"net/http"
	"os"

	"github.com/pior/bubble/authorizationserver"
)

func main() {
	authorizationserver.RegisterHandlers()

	port := "5000"
	if os.Getenv("PORT") != "" {
		port = os.Getenv("PORT")
	}

	log.Fatal(http.ListenAndServe(":"+port, nil))
}
