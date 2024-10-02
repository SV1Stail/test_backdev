package db

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/jackc/pgx/v4/pgxpool"
)

var pool *pgxpool.Pool

func Connect() {
	User := os.Getenv("DB_USER")
	Password := os.Getenv("DB_PASSWORD")
	Host := os.Getenv("DB_HOST")
	Port := os.Getenv("DB_PORT")
	Name := os.Getenv("DB_NAME")
	var err error
	pool, err = pgxpool.Connect(context.Background(), fmt.Sprintf("postgres://%s:%s@%s:%s/%s",
		User, Password, Host, Port, Name))
	if err != nil {
		log.Fatalf("Unable to connect to database: %v\n", err)
	}
	log.Println("Connected to database successfully")
}
func Close() {
	pool.Close()
}
func GetPool() *pgxpool.Pool {
	return pool
}
