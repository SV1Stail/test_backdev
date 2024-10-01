package third

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/SV1Stail/test_backdev/db"
)

// delete all rows where Refrash hash old
func RemoveOldRefrashHash(w http.ResponseWriter, r *http.Request) {
	pool := db.GetPool()
	ctx := context.Background()
	conn, err := pool.Acquire(ctx)
	if err != nil {
		http.Error(w, "cant make conn", http.StatusInternalServerError)
		return
	}
	defer conn.Release()
	ta, err := conn.Begin(ctx)
	defer ta.Rollback(ctx)
	if err != nil {
		http.Error(w, fmt.Sprintf("cant begin tranaction %v", err), http.StatusInternalServerError)
		return
	}
	_, err = ta.Exec(ctx, "DELETE FROM refresh_tokens WHERE expires_at < NOW()")
	if err != nil {
		http.Error(w, fmt.Sprintf("cant DELETE FROM refresh_tokens %v", err), http.StatusInternalServerError)
		return
	}
	err = ta.Commit(ctx)
	if err != nil {
		http.Error(w, fmt.Sprintf("cant commit tranaction %v", err), http.StatusInternalServerError)
		return
	}
	resp := map[string]string{
		"data": "deletion of old data was successful",
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, "cant write resp", http.StatusInternalServerError)
	}
}
