package first

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"

	"github.com/SV1Stail/test_backdev/db"
	jwtcommunication "github.com/SV1Stail/test_backdev/jwtCommunication"
)

func HandlerFirst(w http.ResponseWriter, r *http.Request) {
	var user jwtcommunication.UserInfo
	user.UserID = r.URL.Query().Get("user_id")
	var err error
	user.UserIP, _, err = net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		http.Error(w, "invalid IP address", http.StatusInternalServerError)
		return
	}

	if err := user.IsValid(); err != nil {
		http.Error(w, fmt.Sprintf("error: %v", err), http.StatusBadRequest)
		return
	}

	var wg sync.WaitGroup
	wg.Add(2)
	var aToken, rToken string
	var Aerr, Rerr error
	go func() {
		defer wg.Done()
		aToken, Aerr = jwtcommunication.AccessToken(&user)
	}()

	go func() {
		defer wg.Done()
		rToken, Rerr = jwtcommunication.RefreshToken(&user)
	}()

	wg.Wait()
	if Aerr != nil || Rerr != nil {
		http.Error(w, "can not create aToken or rToken", http.StatusInternalServerError)
		return
	}
	ctx := context.Background()
	pool := db.GetPool()
	if err := user.SaveRefHash(ctx, pool); err != nil {
		http.Error(w, fmt.Sprintf("cant insert into db: %v", err), http.StatusInternalServerError)
		return
	}

	resp := map[string]string{
		"access_token":  aToken,
		"refresh_token": rToken,
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, "cant write resp", http.StatusInternalServerError)
	}
}
