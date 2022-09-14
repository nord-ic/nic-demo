package main

import (
	"fmt"
	"net/http"
)

const demoVer = "0.0.0"

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello world, this is demo version %s", demoVer)
	})
	http.ListenAndServe(":8080", nil)
}
