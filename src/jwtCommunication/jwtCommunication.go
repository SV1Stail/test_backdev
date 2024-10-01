package jwtcommunication

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

var jwtSecret = []byte("your-secret-key")

type User interface {
	isValid() (bool, error)
}

type UserInfo struct {
	UserID           string
	UserIP           string
	Created_at       time.Time
	Expires_at       time.Time
	TokenID          string
	HashRefreshToken string
	mu               sync.Mutex
}

func GetSecret() []byte {
	return jwtSecret
}

// generate Refrash token
// return Refrash token and string
// adding Refrash hash in struct UserInfo
func RefreshToken(user *UserInfo) (string, error) {
	str := make([]byte, 32)

	_, err := rand.Read(str)
	if err != nil {
		return "", err
	}
	refreshToken := base64.URLEncoding.EncodeToString(str)
	hashRefreshToken, err := bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	user.mu.Lock()
	user.HashRefreshToken = string(hashRefreshToken)
	user.mu.Unlock()

	return refreshToken, nil
}

// generate Access token
// return Access token and error
// adding Access token id, time of creation and time of expiration in struct UserInfo
func AccessToken(user *UserInfo) (string, error) {

	token := jwt.New(jwt.SigningMethodHS512)
	claims := token.Claims.(jwt.MapClaims)
	tokenID := uuid.New().String()
	claims["token_id"] = tokenID
	claims["user_id"] = user.UserID
	claims["ip"] = user.UserIP
	timeNow := time.Now()
	claims["exp"] = timeNow.Add(time.Minute * 15).Unix()
	claims["iat"] = timeNow.Unix()

	user.mu.Lock()
	user.TokenID = tokenID
	user.Expires_at = timeNow.Add(time.Minute * 15)
	user.Created_at = timeNow
	user.mu.Unlock()

	return token.SignedString(jwtSecret)
}

// validation UserInfo.UserID, UserInfo.UserIP
// return: all good true,nil
func (user *UserInfo) IsValid() (bool, error) {
	if user.UserID == "" {
		return false, fmt.Errorf("user_id is empty")
	}
	_, err := uuid.Parse(user.UserID)
	if err != nil {
		return false, err
	}
	ip := net.ParseIP(user.UserIP)
	if ip == nil {
		return false, fmt.Errorf("invalid IP address")
	}
	return true, nil
}

func (u *UserInfo) IsMapClaimsValid(mapka jwt.MapClaims) error {
	var ok bool
	u.UserID, ok = mapka["user_id"].(string)
	if !ok {
		return fmt.Errorf("user_id not found in access token")
	}
	u.UserIP, ok = mapka["ip"].(string)
	if !ok {
		return fmt.Errorf("user_ip not found in access token")
	}
	u.TokenID, ok = mapka["token_id"].(string)
	if !ok {
		return fmt.Errorf("token_id not found in access token")
	}
	exp, ok := mapka["exp"].(float64)
	if !ok {
		return fmt.Errorf("expires_at time not found in access token")
	}
	u.Expires_at = time.Unix(int64(exp), 0)
	cre, ok := mapka["iat"].(float64)
	if !ok {
		return fmt.Errorf("ereated_at time not found in access token")
	}
	u.Created_at = time.Unix(int64(cre), 0)
	if ok, err := u.IsValid(); !ok || err != nil {
		return fmt.Errorf("%v", err)
	}
	return nil
}

// get refresh hash from db
func (u *UserInfo) GetRefreshHash(ctx context.Context, pool *pgxpool.Pool) (string, error) {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return "", err
	}
	defer conn.Release()
	var rHash string
	err = conn.QueryRow(ctx, "SELECT refresh_token_hash FROM refresh_tokens WHERE token_id=$1 AND user_id=$2", u.TokenID, u.UserID).Scan(&rHash)
	if err == pgx.ErrNoRows {
		return "", fmt.Errorf("no rows with this user_id and post_id")
	} else if err != nil {
		return "", err
	}
	return rHash, nil
}

func (u *UserInfo) DeleteUsedRefreshHash(ctx context.Context, pool *pgxpool.Pool) error {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	_, err = conn.Exec(ctx, "DELETE FROM refresh_tokens ")
}
