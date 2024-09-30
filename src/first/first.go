package first

import (
	"context"
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

	if ok, err := user.IsValid(); !ok {
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
	saveRefHash(ctx, &user)

	resp := fmt.Sprintf(`{"access_token": "%s", "refresh_token": "%s"}`, aToken, rToken)
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(resp))
}

// save user info in db's table
func saveRefHash(ctx context.Context, user *jwtcommunication.UserInfo) error {
	pool := db.GetPool()
	ta, err := pool.Begin(ctx)
	if err != nil {
		return err
	}

	defer func() {
		if err != nil {
			ta.Rollback(ctx)
		}
	}()

	_, err = ta.Exec(ctx, "INSERT INTO refresh_tokens (user_id, refresh_token_hash, ip_address, created_at, expires_at,token_id) VALUES ($1, $2, $3, $4, $5, $6)",
		user.UserID, user.HashRefreshToken, user.UserIP, user.Created_at, user.Expires_at, user.TokenID)
	if err != nil {
		return err
	}
	err = ta.Commit(ctx)
	if err != nil {
		return err
	}

	return nil
}
