package main

import (
	"fmt"
	"net/http"
)

const demoVer = "1.1.0"

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello world, this is a demo, version %s", demoVer)
	})
	http.ListenAndServe(":8080", nil)
}
