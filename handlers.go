package main

import (
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/fiatjaf/eventstore/sqlite3"
	"github.com/gorilla/mux"
	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"
	"golang.org/x/exp/rand"
)

func AddSubkeyHandler(w http.ResponseWriter, r *http.Request) {
	var subkey struct {
		Privkey      string `json:"privkey"`
		AllowedKinds string `json:"allowed_kinds"`
		Name         string `json:"name"`
	}

	if err := json.NewDecoder(r.Body).Decode(&subkey); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	pubkey, err := nostr.GetPublicKey(subkey.Privkey)
	if err != nil {
		log.Printf("Failed to derive public key: %v", err)
		http.Error(w, "Invalid private key", http.StatusBadRequest)
		return
	}

	now := time.Now().Unix()
	_, err = subkeyDB.Exec("INSERT OR REPLACE INTO subkeys (pubkey, privkey, name, allowed_kinds, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
		pubkey, subkey.Privkey, subkey.Name, subkey.AllowedKinds, now, now)
	if err != nil {
		log.Printf("Failed to add subkey: %v", err)
		http.Error(w, "Failed to add subkey", http.StatusInternalServerError)
		return
	}

	log.Printf("Added new subkey: Pubkey: %s, Name: %s, Allowed Kinds: %s", pubkey, subkey.Name, subkey.AllowedKinds)

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"status": "success", "message": "Subkey added successfully", "pubkey": pubkey})
}

func GetSubkeysHandler(w http.ResponseWriter, r *http.Request) {
	rows, err := subkeyDB.Query("SELECT pubkey, privkey, name, allowed_kinds, created_at, updated_at FROM subkeys")
	if err != nil {
		http.Error(w, "Failed to fetch subkeys", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var subkeys []map[string]interface{}
	for rows.Next() {
		var pubkey, privkey, name, allowedKinds string
		var createdAt, updatedAt int64
		if err := rows.Scan(&pubkey, &privkey, &name, &allowedKinds, &createdAt, &updatedAt); err != nil {
			http.Error(w, "Failed to scan subkey", http.StatusInternalServerError)
			return
		}
		npub, _ := nip19.EncodePublicKey(pubkey)
		nsec, _ := nip19.EncodePrivateKey(privkey)
		subkeys = append(subkeys, map[string]interface{}{
			"pubkey":        pubkey,
			"npub":          npub,
			"privkey":       privkey,
			"nsec":          nsec,
			"name":          name,
			"allowed_kinds": allowedKinds,
			"created_at":    createdAt,
			"updated_at":    updatedAt,
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

func UpdateSubkeyKindsHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	pubkey := vars["pubkey"]

	var update struct {
		AllowedKinds string `json:"allowed_kinds"`
	}
	if err := json.NewDecoder(r.Body).Decode(&update); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	_, err := subkeyDB.Exec("UPDATE subkeys SET allowed_kinds = ? WHERE pubkey = ?", update.AllowedKinds, pubkey)
	if err != nil {
		log.Printf("Failed to update subkey kinds: %v", err)
		http.Error(w, "Failed to update subkey kinds", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "success", "message": "Subkey kinds updated successfully"})
}

func UpdateSubkeyNameHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	pubkey := vars["pubkey"]

	var update struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&update); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	now := time.Now().Unix()
	_, err := subkeyDB.Exec("UPDATE subkeys SET name = ?, updated_at = ? WHERE pubkey = ?", update.Name, now, pubkey)
	if err != nil {
		log.Printf("Failed to update subkey name: %v", err)
		http.Error(w, "Failed to update subkey name", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "success", "message": "Subkey name updated successfully"})
}

func GenerateSubkeyHandler(w http.ResponseWriter, r *http.Request) {
	privateKey := make([]byte, 32)
	_, err := rand.Read(privateKey)
	if err != nil {
		http.Error(w, "Failed to generate private key", http.StatusInternalServerError)
		return
	}

	privKeyHex := hex.EncodeToString(privateKey)
	pubkey, err := nostr.GetPublicKey(privKeyHex)
	if err != nil {
		http.Error(w, "Failed to derive public key", http.StatusInternalServerError)
		return
	}

	name := generateRandomName()
	allowedKinds := "1,4"

	response := map[string]string{
		"name":          name,
		"privkey":       privKeyHex,
		"pubkey":        pubkey,
		"allowed_kinds": allowedKinds,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func generateRandomName() string {
	adjectives := []string{"Swift", "Bright", "Clever", "Daring", "Eager", "Fierce", "Gentle", "Happy", "Jolly", "Kind"}
	nouns := []string{"Fox", "Bear", "Wolf", "Eagle", "Hawk", "Lion", "Tiger", "Panda", "Koala", "Owl"}

	randomAdjective := adjectives[rand.Intn(len(adjectives))]
	randomNoun := nouns[rand.Intn(len(nouns))]

	return randomAdjective + randomNoun
}
