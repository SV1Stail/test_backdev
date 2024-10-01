package db

import (
	"context"
	"fmt"
	"log"

	"github.com/jackc/pgx/v4/pgxpool"
)

var pool *pgxpool.Pool

const DB_USER string = "user_db"
const DB_PASSWORD string = "1234"
const DB_PORT string = "5432"
const DB_NAME string = "backdev"
const DB_HOST string = "localhost"

func Connect() {
	var err error
	pool, err = pgxpool.Connect(context.Background(), fmt.Sprintf("postgres://%s:%s@%s:%s/%s",
		DB_USER, DB_PASSWORD, DB_HOST, DB_PORT, DB_NAME))
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
