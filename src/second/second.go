package second

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/SV1Stail/test_backdev/db"
	jwtcommunication "github.com/SV1Stail/test_backdev/jwtCommunication"
	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
)

type Tokens struct {
	AToken string
	RToken string
}

func HandlerSecond(w http.ResponseWriter, r *http.Request) {
	var tokens Tokens
	tokens.AToken = r.Header.Get("Authorization")
	tokens.RToken = r.FormValue("refresh_token")
	if err := tokens.IsEmpty(); err != nil {
		http.Error(w, fmt.Sprintf("error: %v", err), http.StatusBadRequest)
		return
	}
	tokens.AToken = strings.TrimPrefix(tokens.AToken, "Bearer ")

	token, err := jwt.Parse(tokens.AToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("wrong signing method %v", token.Header["alg"])
		}
		return jwtcommunication.GetSecret(), nil
	})
	if err != nil || !token.Valid {
		http.Error(w, "invalid access token", http.StatusUnauthorized)
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		http.Error(w, "invalid access token claims", http.StatusUnauthorized)
		return
	}

	var tokenInfo jwtcommunication.UserInfo
	if err := tokenInfo.IsMapClaimsValid(claims); err != nil {
		http.Error(w, fmt.Sprintf("%v", err), http.StatusUnauthorized)
		return
	}

	if (tokenInfo.ExpiresAt).Unix() < time.Now().Unix() {
		http.Error(w, "access token expired", http.StatusUnauthorized)
		return
	}

	curIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		http.Error(w, "invalid ip addr", http.StatusInternalServerError)
		return
	}
	if curIP != tokenInfo.UserIP {
		sendMail(&tokenInfo, curIP)
	}

	pool := db.GetPool()
	ctx := context.Background()

	rHash, err := tokenInfo.GetRefreshHash(ctx, pool)
	if err != nil {
		http.Error(w, fmt.Sprintf("refresh token not found  %v", err), http.StatusUnauthorized)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(rHash), []byte(tokens.RToken))
	if err != nil {
		http.Error(w, "invalid refresh token", http.StatusUnauthorized)
		return
	}

	if err := tokenInfo.DeleteUsedRefreshHash(ctx, pool); err != nil {
		http.Error(w, fmt.Sprintf("cant delete rToken %v", err), http.StatusInternalServerError)
		return
	}

	tokenInfo.UserIP = curIP
	var wg sync.WaitGroup

	var aToken, rToken string
	var Aerr, Rerr error

	wg.Add(2)
	go func() {
		defer wg.Done()
		aToken, Aerr = jwtcommunication.AccessToken(&tokenInfo)
	}()
	go func() {
		defer wg.Done()
		rToken, Rerr = jwtcommunication.RefreshToken(&tokenInfo)
	}()
	wg.Wait()
	if Aerr != nil || Rerr != nil {
		http.Error(w, "can not create aToken or rToken", http.StatusInternalServerError)
		return
	}
	if err = tokenInfo.SaveRefHash(ctx, pool); err != nil {
		http.Error(w, fmt.Sprintf("cant save in refresh token in db: %v", err), http.StatusInternalServerError)
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

// send mail if ip was changed
func sendMail(user *jwtcommunication.UserInfo, curIP string) {
	fmt.Printf("for user %s ip was changed from %s on %s ", user.UserID, user.UserIP, curIP)
}

// if one of tokens is empty return true
func (t Tokens) IsEmpty() error {
	if t.AToken == "" {
		return fmt.Errorf("empty access token")
	}
	if t.RToken == "" {
		return fmt.Errorf("empty refresh token")
	}
	return nil
}
