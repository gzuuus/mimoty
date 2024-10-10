package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/fiatjaf/eventstore/sqlite3"
	"github.com/gorilla/mux"
	"github.com/nbd-wtf/go-nostr"
)

func AddSubkeyHandler(w http.ResponseWriter, r *http.Request) {
	var subkey struct {
		Privkey      string `json:"privkey"`
		AllowedKinds string `json:"allowed_kinds"`
	}

	if err := json.NewDecoder(r.Body).Decode(&subkey); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Derive public key from private key
	pubkey, err := nostr.GetPublicKey(subkey.Privkey)
	if err != nil {
		log.Printf("Failed to derive public key: %v", err)
		http.Error(w, "Invalid private key", http.StatusBadRequest)
		return
	}

	_, err = subkeyDB.Exec("INSERT OR REPLACE INTO subkeys (pubkey, privkey, allowed_kinds) VALUES (?, ?, ?)",
		pubkey, subkey.Privkey, subkey.AllowedKinds)
	if err != nil {
		log.Printf("Failed to add subkey: %v", err)
		http.Error(w, "Failed to add subkey", http.StatusInternalServerError)
		return
	}

	log.Printf("Added new subkey: Pubkey: %s, Allowed Kinds: %s", pubkey, subkey.AllowedKinds)

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"status": "success", "message": "Subkey added successfully", "pubkey": pubkey})
}

func GetSubkeysHandler(w http.ResponseWriter, r *http.Request) {
	rows, err := subkeyDB.Query("SELECT pubkey, privkey, allowed_kinds FROM subkeys")
	if err != nil {
		http.Error(w, "Failed to fetch subkeys", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var subkeys []map[string]string
	for rows.Next() {
		var pubkey, privkey, allowedKinds string
		if err := rows.Scan(&pubkey, &privkey, &allowedKinds); err != nil {
			http.Error(w, "Failed to scan subkey", http.StatusInternalServerError)
			return
		}
		subkeys = append(subkeys, map[string]string{
			"pubkey":        pubkey,
			"privkey":       privkey,
			"allowed_kinds": allowedKinds,
		})
	}

	json.NewEncoder(w).Encode(subkeys)
}

func DeleteSubkeyHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	pubkey := vars["pubkey"]

	_, err := subkeyDB.Exec("DELETE FROM subkeys WHERE pubkey = ?", pubkey)
	if err != nil {
		http.Error(w, "Failed to delete subkey", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "success", "message": "Subkey deleted successfully"})
}

func DeleteMultipleSubkeysHandler(w http.ResponseWriter, r *http.Request) {
	var pubkeys []string
	if err := json.NewDecoder(r.Body).Decode(&pubkeys); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if len(pubkeys) == 0 {
		http.Error(w, "No pubkeys provided", http.StatusBadRequest)
		return
	}

	placeholders := make([]string, len(pubkeys))
	args := make([]interface{}, len(pubkeys))
	for i, pubkey := range pubkeys {
		placeholders[i] = "?"
		args[i] = pubkey
	}

	query := fmt.Sprintf("DELETE FROM subkeys WHERE pubkey IN (%s)", strings.Join(placeholders, ","))
	result, err := subkeyDB.Exec(query, args...)
	if err != nil {
		log.Printf("Failed to delete multiple subkeys: %v", err)
		http.Error(w, "Failed to delete subkeys", http.StatusInternalServerError)
		return
	}

	rowsAffected, _ := result.RowsAffected()
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":        "success",
		"message":       "Subkeys deleted successfully",
		"rows_affected": rowsAffected,
	})
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	// Login successful
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}

func initDatabases() error {
	var err error

	// Initialize event database
	eventDB = &sqlite3.SQLite3Backend{DatabaseURL: "events.db"}
	if err := eventDB.Init(); err != nil {
		return fmt.Errorf("failed to initialize event database: %w", err)
	}

	// Initialize subkey database
	subkeyDB, err = sql.Open("sqlite3", "subkeys.db")
	if err != nil {
		return fmt.Errorf("failed to open subkey database: %w", err)
	}

	if err := subkeyDB.Ping(); err != nil {
		return fmt.Errorf("failed to ping subkey database: %w", err)
	}

	if err := CreateSubkeysTable(); err != nil {
		return fmt.Errorf("failed to create subkeys table: %w", err)
	}

	return nil
}

func CreateHomeHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data := struct {
			RelayName        string
			RelayDescription string
			AllowedKinds     []int
			WhitelistEnabled bool
			Host             string
		}{
			RelayName:        relay.Info.Name,
			RelayDescription: relay.Info.Description,
			Host:             r.Host,
		}
		RenderTemplate(w, data)
	}
}
