package jwtcommunication

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
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

// var jwtSecret = []byte(os.Getenv("JWT_SECRET"))
var jwtSecret = []byte("your-secret-key")

type UserInfo struct {
	UserID           string
	UserIP           string
	CreatedAt        time.Time
	ExpiresAt        time.Time
	TokenID          string
	HashRefreshToken string
	mu               sync.Mutex
}

func GetSecret() []byte {
	return jwtSecret
}

// save user info in db's table
func (user *UserInfo) SaveRefHash(ctx context.Context, pool *pgxpool.Pool) error {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()

	ta, err := conn.Begin(ctx)
	if err != nil {
		return err
	}

	defer ta.Rollback(ctx)

	_, err = ta.Exec(ctx, "INSERT INTO refresh_tokens (user_id, refresh_token_hash, ip_address, created_at, expires_at,token_id) VALUES ($1, $2, $3, $4, $5, $6)",
		user.UserID, user.HashRefreshToken, user.UserIP, user.CreatedAt, user.ExpiresAt, user.TokenID)
	if err != nil {
		return err
	}
	err = ta.Commit(ctx)
	if err != nil {
		return err
	}

	return nil
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
	user.ExpiresAt = timeNow.Add(time.Minute * 15)
	user.CreatedAt = timeNow
	user.mu.Unlock()

	return token.SignedString(jwtSecret)
}

// validation UserInfo.UserID, UserInfo.UserIP
// return: all good true,nil
func (user *UserInfo) IsValid() error {
	if user.UserID == "" {
		return fmt.Errorf("user_id is empty")
	}
	_, err := uuid.Parse(user.UserID)
	if err != nil {
		return err
	}
	ip := net.ParseIP(user.UserIP)
	if ip == nil {
		return fmt.Errorf("invalid IP address")
	}
	return nil
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
	exp, ok := mapka["exp"]
	if !ok {
		return fmt.Errorf("ExpiresAt time not found in access token")
	}
	var Val int64
	switch v := exp.(type) {
	case float64:
		Val = int64(v)
	case int64:
		Val = v
	case json.Number:
		var err error
		Val, err = v.Int64()
		if err != nil {
			return fmt.Errorf("cant conver exp %v", err)
		}
	default:
		return fmt.Errorf("invalid exp type")
	}
	u.ExpiresAt = time.Unix(Val, 0)
	cre, ok := mapka["iat"]
	if !ok {
		return fmt.Errorf("ereated_at time not found in access token")
	}
	switch v := cre.(type) {
	case float64:
		Val = int64(v)
	case int64:
		Val = v
	case json.Number:
		var err error
		Val, err = v.Int64()
		if err != nil {
			return fmt.Errorf("cant convert cre %v", err)
		}
	default:
		return fmt.Errorf("invalid cre type")
	}

	u.CreatedAt = time.Unix(Val, 0)
	if err := u.IsValid(); err != nil {
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
		return "", fmt.Errorf("no rows with this user_id and token_id")

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
	ta, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer ta.Rollback(ctx)

	_, err = ta.Exec(ctx, "DELETE FROM refresh_tokens WHERE user_id=$1 AND token_id=$2", u.UserID, u.TokenID)
	if err != nil {
		return err
	}
	err = ta.Commit(ctx)
	if err != nil {
		return err
	}
	return nil
}
