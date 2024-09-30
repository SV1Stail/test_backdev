package second

import (
	"fmt"
	"net"
	"net/http"
	"strings"

	jwtcommunication "github.com/SV1Stail/test_backdev/jwtCommunication"
	"github.com/dgrijalva/jwt-go"
)

type TokenValid interface {
	IsEmpty() (bool, error)
}

// if one of tokens is empty return true
func (t Tokens) IsEmpty() (bool, error) {
	if t.AToken == "" {
		return true, fmt.Errorf("empty access token")
	}
	if t.RToken == "" {
		return true, fmt.Errorf("empty refresh token")
	}
	return false, nil
}

type Tokens struct {
	AToken string
	RToken string
}

func HandlerSecond(w http.ResponseWriter, r *http.Request) {
	var tokens Tokens
	tokens.AToken = r.Header.Get("Authorization")
	tokens.RToken = r.FormValue("refresh_token")
	if ok, err := tokens.IsEmpty(); ok {
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

	curIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		http.Error(w, "invalid ip addr", http.StatusInternalServerError)
		return
	}
	if curIP != tokenInfo.UserIP {
		fmt.Printf("ANOTHER USER IP for user %s", tokenInfo.UserID)
	}

}
