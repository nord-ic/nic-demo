package main

import (
	"fmt"
	"net/http"
)

const useTLS = false

const demoVer = "2.0.0"

func handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(fmt.Sprintf("<h2>Ver: %s</h2>", demoVer)))
	// fmt.Fprintf(w, "This is an example server.\n")
	// io.WriteString(w, "This is an example server.\n")
}

func main() {
	http.HandleFunc("/", handler)
	if useTLS {
		http.ListenAndServeTLS(":8080", "/certs/demo_srvr_cert.pem", "/certs/demo_server_key.pem", nil)
	} else {
		http.ListenAndServe(":8080", nil)
	}
}
