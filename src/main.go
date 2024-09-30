package main

import (
	"net/http"

	"github.com/SV1Stail/test_backdev/db"
	"github.com/SV1Stail/test_backdev/first"
	"github.com/SV1Stail/test_backdev/second"
)

func main() {
	db.Connect()
	defer db.Close()
	rootMux := http.NewServeMux()
	getTokenMux := http.NewServeMux()
	rootMux.Handle("/api/", http.StripPrefix("/api", getTokenMux))
	getTokenMux.HandleFunc("/get_token", first.HandlerFirst)
	getTokenMux.HandleFunc("/refresh_token", second.HandlerSecond)
	http.ListenAndServe(":8080", rootMux)
}
