package main

import (
	"fmt"
	"net/http"

	"github.com/SV1Stail/test_backdev/db"
	"github.com/SV1Stail/test_backdev/first"
	"github.com/SV1Stail/test_backdev/second"
	"github.com/SV1Stail/test_backdev/third"
)

func main() {
	db.Connect()
	defer db.Close()
	rootMux := http.NewServeMux()
	getTokenMux := http.NewServeMux()
	rootMux.Handle("/api/", http.StripPrefix("/api", getTokenMux))
	getTokenMux.HandleFunc("/get_token", first.HandlerFirst) //first path
	getTokenMux.HandleFunc("/refresh_token", second.HandlerSecond) // second path
	getTokenMux.HandleFunc("/remove_old_data", third.RemoveOldRefrashHash) // clean old data in bas
	fmt.Println("listening localhost:8080")
	http.ListenAndServe(":8080", rootMux)

}
