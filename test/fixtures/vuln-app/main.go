package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
)

var db *sql.DB

func main() {
	apiKey := os.Getenv("API_KEY")
	if apiKey == "" {
		apiKey = "sk-1234567890abcdef"
	}

	http.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		query := fmt.Sprintf("SELECT * FROM users WHERE id = '%s'", id)
		rows, err := db.Query(query)
		if err != nil {
			log.Fatal(err)
		}
		defer rows.Close()
	})

	log.Println("Starting server on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
