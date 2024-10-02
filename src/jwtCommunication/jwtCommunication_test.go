package jwtcommunication_test

import (
	"log"
	"testing"

	jwtcommunication "github.com/SV1Stail/test_backdev/jwtCommunication"
	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
)

func TestRefreshToken_1(t *testing.T) {
	var user jwtcommunication.UserInfo
	str, err := jwtcommunication.RefreshToken(&user)
	if err != nil {
		log.Fatalf("UNexpected error: %v", err)
	}
	if str == "" {
		log.Fatalf("FATAL fefresh token is empty")
	}
	if user.HashRefreshToken == "" {
		log.Fatalf("FATAL fefresh HASH in struct is empty")
	}
}

func TestAccessToken_1(t *testing.T) {
	var user jwtcommunication.UserInfo
	user.UserID = "123"
	user.UserIP = "192.168.0.1"
	str, err := jwtcommunication.AccessToken(&user)
	if err != nil {
		log.Fatalf("UNexpected erro_1: %v", err)
	}
	token, err := jwt.Parse(str, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			log.Fatalf("wrong signing method %v", token.Header["alg"])
			// return nil, fmt.Errorf("wrong signing method %v", token.Header["alg"])
		}
		return jwtcommunication.GetSecret(), nil
	})
	if err != nil {
		log.Fatalf("UNexpected error_2: %v", err)
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		log.Fatal("cant make MapClaims")
	}
	if claims["user_id"].(string) != user.UserID {
		log.Fatalf("claims[\"user_id\"] (%s) does not match with original user_id (%s)", claims["user_id"].(string), user.UserID)
	}
	if claims["ip"].(string) != user.UserIP {
		log.Fatalf("claims[\"ip\"] (%s) does not match with original user_id (%s)", claims["ip"].(string), user.UserIP)
	}
}

func TestIsValid_1(t *testing.T) {
	var user jwtcommunication.UserInfo
	user.UserID = ""
	if err := user.IsValid(); err == nil {
		log.Fatal("expected error")
	}
}
func TestIsValid_2(t *testing.T) {
	var user jwtcommunication.UserInfo
	user.UserID = "123"
	if err := user.IsValid(); err == nil {
		log.Fatal("expected error")
	}
}
func TestIsValid_3(t *testing.T) {
	var user jwtcommunication.UserInfo
	user.UserID = uuid.New().String()
	user.UserIP = "192.168.0.1"
	if err := user.IsValid(); err != nil {
		log.Fatal("UNexpected error")
	}
}
func TestIsValid_4(t *testing.T) {
	var user jwtcommunication.UserInfo
	user.UserID = uuid.New().String()
	user.UserIP = "1922.168.0.1"
	if err := user.IsValid(); err == nil {
		log.Fatal("expected error")
	}
}

func TestIsMapClaimsValid(t *testing.T) {
	var user jwtcommunication.UserInfo
	user.UserID = "123"
	user.UserIP = "192.168.0.1"
	str, err := jwtcommunication.AccessToken(&user)
	if err != nil {
		log.Fatalf("UNexpected erro_1: %v", err)
	}
	token, err := jwt.Parse(str, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			log.Fatalf("wrong signing method %v", token.Header["alg"])
			// return nil, fmt.Errorf("wrong signing method %v", token.Header["alg"])
		}
		return jwtcommunication.GetSecret(), nil
	})
	if err != nil {
		log.Fatalf("UNexpected error_2: %v", err)
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		log.Fatal("cant make MapClaims")
	}
	var user2 jwtcommunication.UserInfo
	user2.IsMapClaimsValid(claims)

	if user2.UserID != user.UserID {
		log.Fatalf("user2 (%s) does not match with original user_id (%s)", user2.UserID, user.UserID)
	}
	if user2.UserIP != user.UserIP {
		log.Fatalf("user2 (%s) does not match with original ip (%s)", user2.UserIP, user.UserIP)
	}
	if user2.CreatedAt.IsZero() || user2.ExpiresAt.IsZero() ||
		user2.TokenID == "" {
		log.Fatalf("has zero values")
	}
}
