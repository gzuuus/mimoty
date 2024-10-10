# .gitignore

```
.env
go.sum

# SQLite database files
*.db
```

# events.db

This is a binary file of the type: Binary

# go.mod

```mod
module mimoty-relay

go 1.23.0

toolchain go1.23.2

require (
	github.com/fiatjaf/eventstore v0.11.1
	github.com/fiatjaf/khatru v0.8.3
	github.com/gorilla/mux v1.8.1
	github.com/joho/godotenv v1.5.1
	github.com/mattn/go-sqlite3 v1.14.24
	github.com/nbd-wtf/go-nostr v0.38.2
	github.com/stretchr/testify v1.9.0
)

require (
	github.com/andybalholm/brotli v1.0.5 // indirect
	github.com/btcsuite/btcd/btcec/v2 v2.3.4 // indirect
	github.com/btcsuite/btcd/chaincfg/chainhash v1.1.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/decred/dcrd/crypto/blake256 v1.1.0 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.3.0 // indirect
	github.com/fasthttp/websocket v1.5.7 // indirect
	github.com/gobwas/httphead v0.1.0 // indirect
	github.com/gobwas/pool v0.2.1 // indirect
	github.com/gobwas/ws v1.4.0 // indirect
	github.com/jmoiron/sqlx v1.3.5 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/klauspost/compress v1.17.8 // indirect
	github.com/mailru/easyjson v0.7.7 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/puzpuzpuz/xsync/v3 v3.4.0 // indirect
	github.com/rs/cors v1.7.0 // indirect
	github.com/savsgio/gotils v0.0.0-20230208104028-c358bd845dee // indirect
	github.com/tidwall/gjson v1.17.3 // indirect
	github.com/tidwall/match v1.1.1 // indirect
	github.com/tidwall/pretty v1.2.1 // indirect
	github.com/valyala/bytebufferpool v1.0.0 // indirect
	github.com/valyala/fasthttp v1.51.0 // indirect
	golang.org/x/exp v0.0.0-20240909161429-701f63a606c0 // indirect
	golang.org/x/net v0.21.0 // indirect
	golang.org/x/sys v0.25.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

```

# handlers.go

```go
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

```

# main_test.go

```go
package main

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/fiatjaf/eventstore/sqlite3"
	_ "github.com/mattn/go-sqlite3"
	"github.com/nbd-wtf/go-nostr"
	"github.com/stretchr/testify/assert"
)

const (
	testEventDBPath  = "test_events.db"
	testSubkeyDBPath = "test_subkeys.db"
)

var testSubkeyDB *sql.DB

func TestMain(m *testing.M) {
	// Set up test environment
	setupTestEnvironment()

	// Run tests
	code := m.Run()

	// Clean up
	tearDownTestEnvironment()

	os.Exit(code)
}

func setupTestEnvironment() {
	var err error

	rootPrivateKey = nostr.GeneratePrivateKey()
	os.Setenv("ROOT_PRIVATE_KEY", rootPrivateKey)

	// Initialize test databases
	eventDB = &sqlite3.SQLite3Backend{DatabaseURL: testEventDBPath}
	eventDB.Init()

	testSubkeyDB, err = sql.Open("sqlite3", testSubkeyDBPath)
	if err != nil {
		panic(err)
	}

	_, err = testSubkeyDB.Exec(`
		CREATE TABLE IF NOT EXISTS subkeys (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			pubkey TEXT NOT NULL,
			privkey TEXT NOT NULL,
			allowed_kinds TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		panic(err)
	}

	// Seed test data
	seedTestSubkeys()

	// Set the global subkeyDB to use our test database
	subkeyDB = testSubkeyDB
}

func seedTestSubkeys() {
	testSubkeys := []struct {
		allowedKinds string
	}{
		{"1,2,3"},
		{"1,4,5"},
		{"2,3,4"},
	}

	for _, subkey := range testSubkeys {
		sk := nostr.GeneratePrivateKey()
		pk, _ := nostr.GetPublicKey(sk)

		_, err := testSubkeyDB.Exec("INSERT INTO subkeys (pubkey, privkey, allowed_kinds) VALUES (?, ?, ?)",
			pk, sk, subkey.allowedKinds)
		if err != nil {
			panic(err)
		}
	}
}

func tearDownTestEnvironment() {
	testSubkeyDB.Close()
	os.Remove(testEventDBPath)
	os.Remove(testSubkeyDBPath)
}

func TestValidSubkeyEvent(t *testing.T) {
	var pubkey, allowedKinds string
	err := testSubkeyDB.QueryRow("SELECT pubkey, allowed_kinds FROM subkeys LIMIT 1").Scan(&pubkey, &allowedKinds)
	assert.NoError(t, err)

	event := &nostr.Event{
		PubKey:    pubkey,
		CreatedAt: nostr.Timestamp(time.Now().Unix()),
		Kind:      1,
		Content:   "Test content",
	}

	assert.True(t, isValidSubkeyEvent(event))
}

func TestInvalidSubkeyEvent(t *testing.T) {
	var pubkey, allowedKinds string
	err := testSubkeyDB.QueryRow("SELECT pubkey, allowed_kinds FROM subkeys LIMIT 1").Scan(&pubkey, &allowedKinds)
	assert.NoError(t, err)

	event := &nostr.Event{
		PubKey:    pubkey,
		CreatedAt: nostr.Timestamp(time.Now().Unix()),
		Kind:      9999,
		Content:   "Test content",
	}

	assert.False(t, isValidSubkeyEvent(event))
}

func TestRandomPubkeyEvent(t *testing.T) {
	randomPubkey, _ := nostr.GetPublicKey(nostr.GeneratePrivateKey())

	event := &nostr.Event{
		PubKey:    randomPubkey,
		CreatedAt: nostr.Timestamp(time.Now().Unix()),
		Kind:      1,
		Content:   "Test content",
	}

	assert.False(t, isValidSubkeyEvent(event))
}

func TestStoreAndResignEvent(t *testing.T) {
	var pubkey, allowedKinds string
	err := testSubkeyDB.QueryRow("SELECT pubkey, allowed_kinds FROM subkeys LIMIT 1").Scan(&pubkey, &allowedKinds)
	assert.NoError(t, err)

	event := &nostr.Event{
		PubKey:    pubkey,
		CreatedAt: nostr.Timestamp(time.Now().Unix()),
		Kind:      1,
		Content:   "Test content",
	}

	err = storeEvent(context.Background(), event)
	assert.NoError(t, err)

	rootPubkey, _ := nostr.GetPublicKey(rootPrivateKey)
	storedEvents, err := eventDB.QueryEvents(context.Background(), nostr.Filter{
		Authors: []string{rootPubkey},
		Kinds:   []int{1},
	})
	assert.NoError(t, err)

	storedEvent := <-storedEvents
	assert.Equal(t, rootPubkey, storedEvent.PubKey)
	assert.Equal(t, event.Content, storedEvent.Content)
	assert.Equal(t, event.Kind, storedEvent.Kind)
}

func TestRejectInvalidEvent(t *testing.T) {
	randomPubkey, _ := nostr.GetPublicKey(nostr.GeneratePrivateKey())

	event := &nostr.Event{
		PubKey:    randomPubkey,
		CreatedAt: nostr.Timestamp(time.Now().Unix()),
		Kind:      1,
		Content:   "Test content",
	}

	err := storeEvent(context.Background(), event)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "event not allowed for this subkey")
}

```

# main.go

```go
package main

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fiatjaf/eventstore/sqlite3"
	"github.com/fiatjaf/khatru"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	_ "github.com/mattn/go-sqlite3"
	"github.com/nbd-wtf/go-nostr"
)

var (
	eventDB        *sqlite3.SQLite3Backend
	subkeyDB       *sql.DB
	relay          *khatru.Relay
	rootPrivateKey string
	// rebroadcastRelays []string
	rootPublicKey string
	templates     *template.Template
)

func main() {
	if err := initApp(); err != nil {
		log.Fatalf("Failed to initialize application: %v", err)
	}

	r := setupRoutes()

	log.Println("Starting server on :3334")
	if err := http.ListenAndServe(":3334", r); err != nil {
		log.Fatal(err)
	}
}

func setupRoutes() *mux.Router {
	r := mux.NewRouter()
	r.HandleFunc("/", homeHandler).Methods("GET")
	r.HandleFunc("/api/login", authMiddleware(LoginHandler)).Methods("POST")
	r.HandleFunc("/api/subkeys", authMiddleware(GetSubkeysHandler)).Methods("GET")
	r.HandleFunc("/api/subkey", authMiddleware(AddSubkeyHandler)).Methods("POST")
	r.HandleFunc("/api/subkey/{pubkey}", authMiddleware(DeleteSubkeyHandler)).Methods("DELETE")
	r.HandleFunc("/api/subkeys/delete", authMiddleware(DeleteMultipleSubkeysHandler)).Methods("POST")
	r.PathPrefix("/relay").Handler(relay)

	return r
}

func initApp() error {
	if err := godotenv.Load(); err != nil {
		return fmt.Errorf("error loading .env file: %w", err)
	}

	rootPrivateKey = os.Getenv("ROOT_PRIVATE_KEY")
	if rootPrivateKey == "" {
		return fmt.Errorf("ROOT_PRIVATE_KEY not set in environment")
	}

	var err error
	rootPublicKey, err = nostr.GetPublicKey(rootPrivateKey)
	if err != nil {
		return fmt.Errorf("failed to get root public key: %w", err)
	}

	// rebroadcastRelaysStr := os.Getenv("REBROADCAST_RELAYS")
	// rebroadcastRelays = strings.Split(rebroadcastRelaysStr, ",")

	if err := initDatabases(); err != nil {
		return fmt.Errorf("failed to initialize databases: %w", err)
	}

	relay = khatru.NewRelay()
	setupRelay()

	if err := initTemplates(); err != nil {
		return fmt.Errorf("failed to initialize templates: %w", err)
	}

	return nil
}
func initTemplates() error {
	var err error
	templatesDir := "templates"
	templates, err = template.ParseFiles(filepath.Join(templatesDir, "home.html"))
	if err != nil {
		return fmt.Errorf("failed to parse templates: %w", err)
	}
	return nil
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	data := struct {
		Title            string
		RelayName        string
		RelayDescription string
		Host             string
	}{
		Title:            "Subkey Management",
		RelayName:        relay.Info.Name,
		RelayDescription: relay.Info.Description,
		Host:             r.Host,
	}
	err := templates.ExecuteTemplate(w, "home.html", data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Nostr ") {
			http.Error(w, "Invalid authorization header", http.StatusUnauthorized)
			return
		}

		eventJSON, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(authHeader, "Nostr "))
		if err != nil {
			http.Error(w, "Invalid token encoding", http.StatusUnauthorized)
			return
		}

		var event nostr.Event
		if err := json.Unmarshal(eventJSON, &event); err != nil {
			http.Error(w, "Invalid token format", http.StatusUnauthorized)
			return
		}

		// Validate event
		if event.Kind != 27235 {
			http.Error(w, "Invalid event kind", http.StatusUnauthorized)
			return
		}

		if event.PubKey != rootPublicKey {
			http.Error(w, "Unauthorized pubkey", http.StatusUnauthorized)
			return
		}

		// Check if the event's URL and method match the current request
		validRequest := false
		for _, tag := range event.Tags {
			if len(tag) >= 2 && tag[0] == "u" && tag[1] == r.URL.String() {
				validRequest = true
				break
			}
		}
		if !validRequest {
			http.Error(w, "Invalid request URL", http.StatusUnauthorized)
			return
		}

		// Verify signature
		ok, err := event.CheckSignature()
		if err != nil || !ok {
			http.Error(w, "Invalid signature", http.StatusUnauthorized)
			return
		}

		// Check if the event is not too old (e.g., within the last 5 minutes)
		if time.Now().Unix()-int64(event.CreatedAt) > 300 {
			http.Error(w, "Token expired", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	}
}

func setupRelay() {
	relay.StoreEvent = append(relay.StoreEvent, storeEvent)
	relay.QueryEvents = append(relay.QueryEvents, eventDB.QueryEvents)
	relay.DeleteEvent = append(relay.DeleteEvent, eventDB.DeleteEvent)
	relay.RejectEvent = append(relay.RejectEvent, validateEvent)

	relay.Info.Name = "Your Relay Name"
	relay.Info.Description = "Your Relay Description"
}

func storeEvent(ctx context.Context, event *nostr.Event) error {
	log.Printf("Attempting to store event: %+v", event)
	if !isValidSubkeyEvent(event) {
		log.Printf("Event not allowed for subkey %s", event.PubKey)
		return fmt.Errorf("event not allowed for this subkey")
	}

	resignedEvent, err := resignEvent(event)
	if err != nil {
		return fmt.Errorf("failed to re-sign event: %w", err)
	}

	if err := eventDB.SaveEvent(ctx, resignedEvent); err != nil {
		return fmt.Errorf("failed to save event: %w", err)
	}

	// go rebroadcastEvent(resignedEvent)

	return nil
}

func validateEvent(ctx context.Context, event *nostr.Event) (bool, string) {
	if !isValidSubkeyEvent(event) {
		return true, "event not allowed for this subkey"
	}
	return false, ""
}

func isValidSubkeyEvent(event *nostr.Event) bool {
	log.Printf("Checking event: %+v", event)
	var allowedKinds string
	err := subkeyDB.QueryRow("SELECT allowed_kinds FROM subkeys WHERE pubkey = ?", event.PubKey).Scan(&allowedKinds)
	if err != nil {
		if err == sql.ErrNoRows {
			log.Printf("No subkey found for pubkey %s", event.PubKey)
		} else {
			log.Printf("Error querying subkey for pubkey %s: %v", event.PubKey, err)
		}
		return false
	}
	log.Printf("Allowed kinds for pubkey %s: %s", event.PubKey, allowedKinds)

	kinds := strings.Split(allowedKinds, ",")
	for _, kind := range kinds {
		if fmt.Sprintf("%d", event.Kind) == strings.TrimSpace(kind) {
			log.Printf("Event kind %d is allowed", event.Kind)
			return true
		}
	}
	log.Printf("Event kind %d is not allowed", event.Kind)
	return false
}

func resignEvent(event *nostr.Event) (*nostr.Event, error) {
	resignedEvent := *event
	pubkey, err := nostr.GetPublicKey(rootPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get public key: %w", err)
	}
	resignedEvent.PubKey = pubkey
	resignedEvent.CreatedAt = nostr.Timestamp(time.Now().Unix())
	if err := resignedEvent.Sign(rootPrivateKey); err != nil {
		return nil, err
	}
	return &resignedEvent, nil
}

// func rebroadcastEvent(event *nostr.Event) {
// 	for _, url := range rebroadcastRelays {
// 		relay, err := nostr.RelayConnect(context.Background(), url)
// 		if err != nil {
// 			log.Printf("Failed to connect to relay %s: %v", url, err)
// 			continue
// 		}
// 		defer relay.Close()

// 		if err := relay.Publish(context.Background(), *event); err != nil {
// 			log.Printf("Failed to publish event to relay %s: %v", url, err)
// 		}
// 	}
// }

```

# seed.go

```go
package main

import (
	"log"

	_ "github.com/mattn/go-sqlite3"
	"github.com/nbd-wtf/go-nostr"
)

func SeedSubkeys() {
	// Generate and insert test subkeys
	testSubkeys := []struct {
		allowedKinds string
	}{
		{"1,2,3"},
		{"1,4,5"},
		{"2,3,4"},
	}

	for _, subkey := range testSubkeys {
		sk := nostr.GeneratePrivateKey()
		pk, err := nostr.GetPublicKey(sk)
		if err != nil {
			log.Printf("Failed to derive public key: %v", err)
			continue
		}

		_, err = subkeyDB.Exec("INSERT OR REPLACE INTO subkeys (pubkey, privkey, allowed_kinds) VALUES (?, ?, ?)",
			pk, sk, subkey.allowedKinds)
		if err != nil {
			log.Printf("Failed to insert subkey: %v", err)
		} else {
			log.Printf("Inserted subkey: %s with allowed kinds: %s", pk, subkey.allowedKinds)
		}
	}

	log.Println("Subkeys database initialized with test data")
}

```

# subkeys.db

This is a binary file of the type: Binary

# subkeysdb.go

```go
package main

func CreateSubkeysTable() error {
	_, err := subkeyDB.Exec(`
		CREATE TABLE IF NOT EXISTS subkeys (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			pubkey TEXT NOT NULL UNIQUE,
			privkey TEXT NOT NULL,
			allowed_kinds TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)
	`)
	return err
}

```

# templates/base.html

```html
<!-- templates/base.html -->
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{.Title}}</title>
    <script src="https://unpkg.com/htmx.org@1.9.2"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js"></script>
    <style>
        /* Your CSS here */
    </style>
</head>
<body>
    {{template "content" .}}    
    {{block "scripts" .}}{{end}}
</body>
</html>
```

# templates/home.html

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{.RelayName}} - Subkey Management</title>
    <script src="https://unpkg.com/nostr-tools/lib/nostr.bundle.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js"></script>

    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f4f4f4;
        }
        .container {
            background-color: #fff;
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        h1, h2 {
            color: #2c3e50;
        }
        .card {
            background-color: #fff;
            border: 1px solid #ddd;
            border-radius: 4px;
            padding: 15px;
            margin-bottom: 20px;
        }
        .input, .button {
            width: 100%;
            padding: 10px;
            margin-bottom: 10px;
            border: 1px solid #ddd;
            border-radius: 4px;
        }
        .button {
            background-color: #3498db;
            color: #fff;
            border: none;
            cursor: pointer;
        }
        .button:hover {
            background-color: #2980b9;
        }
        .subkey-list {
            margin-top: 20px;
            overflow-x: auto;
        }
        .subkey-table {
            width: 100%;
            border-collapse: collapse;
        }
        .subkey-table th, .subkey-table td {
            border: 1px solid #ddd;
            padding: 8px;
            text-align: left;
        }
        .subkey-table th {
            background-color: #f2f2f2;
        }
        .qr-code {
            display: none;
            margin-top: 10px;
        }
        .show-qr, .show-qr-priv, .hide-qr {
            background-color: #2ecc71;
            margin-left: 10px;
        }
        .hide-qr, .hide-qr-priv {
            display: none;
        }
        .checkbox-column {
            width: 30px;
        }
        .key-column {
            max-width: 200px;
            word-break: break-all;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>{{.RelayName}} - Subkey Management</h1>
        
        <div class="card">
            <h2>Relay Information</h2>
            <p>{{.RelayDescription}}</p>
            <p><strong>Connect to this relay using:</strong> <code>ws://{{.Host}}/relay</code></p>
        </div>

        <div class="card" id="login-section">
            <h2>Login</h2>
            <button id="login-button" class="button">Login with Nostr</button>
        </div>

        <div class="card" id="subkey-management" style="display: none;">
            <h2>Manage Subkeys</h2>
            <form id="add-subkey-form">
                <input type="text" name="privkey" placeholder="Private Key (nsec or hex)" class="input" required>
                <input type="text" name="allowed_kinds" placeholder="Allowed Kinds (comma-separated)" class="input" required>
                <button type="submit" class="button">Add Subkey</button>
            </form>

            <div id="subkey-list" class="subkey-list">
                <table class="subkey-table">
                    <thead>
                        <tr>
                            <th class="checkbox-column"><input type="checkbox" id="select-all"></th>
                            <th>Public Key</th>
                            <th>Private Key</th>
                            <th>Allowed Kinds</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody id="subkey-table-body">
                        <!-- Subkeys will be loaded here -->
                    </tbody>
                </table>
                <button id="delete-selected" class="button" style="display: none;">Delete Selected</button>
            </div>
        </div>
    </div>

<script>
    const tokenCache = new Map();

    async function getAuthToken(url, method) {
        const cacheKey = url + ':' + method;
        if (tokenCache.has(cacheKey)) {
            const cachedToken = tokenCache.get(cacheKey);
            if (Date.now() - cachedToken.timestamp < 4 * 60 * 1000) { // 4 minutes
                return cachedToken.token;
            }
        }
        
        const token = await generateAuthToken(url, method);
        tokenCache.set(cacheKey, { token, timestamp: Date.now() });
        return token;
    }

    async function generateAuthToken(url, method) {
        const authEvent = {
            kind: 27235,
            created_at: Math.floor(Date.now() / 1000),
            tags: [["u", url], ["method", method]],
            content: ""
        };
        const signedEvent = await window.nostr.signEvent(authEvent);
        return btoa(JSON.stringify(signedEvent));
    }

    async function login() {
        try {
            const token = await getAuthToken('/api/login', 'POST');
            const response = await fetch('/api/login', {
                method: 'POST',
                headers: {
                    'Authorization': 'Nostr ' + token
                }
            });

            if (response.ok) {
                document.getElementById('login-section').style.display = 'none';
                document.getElementById('subkey-management').style.display = 'block';
                loadSubkeys();
            } else {
                throw new Error('Login failed');
            }
        } catch (err) {
            console.error('Login failed:', err);
            alert('Login failed. Make sure you have the correct Nostr extension installed and are using the root key.');
        }
    }

    async function loadSubkeys() {
        const token = await getAuthToken('/api/subkeys', 'GET');
        const response = await fetch('/api/subkeys', {
            headers: {
                'Authorization': 'Nostr ' + token
            }
        });
        const subkeys = await response.json();
        const subkeyTableBody = document.getElementById('subkey-table-body');
        subkeyTableBody.innerHTML = '';
        subkeys.forEach(subkey => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td><input type="checkbox" class="subkey-checkbox" data-pubkey="${subkey.pubkey}"></td>
                <td class="key-column">
                    ${subkey.pubkey}
                    <br>
                    <button class="show-qr" onclick="showQR(this, '${subkey.pubkey}')">Show QR</button>
                    <button class="hide-qr" onclick="hideQR(this)">Hide QR</button>
                    <div class="qr-code"></div>
                </td>
                <td class="key-column">
                    ${subkey.privkey}
                    <br>
                    <button class="show-qr-priv" onclick="showQR(this, '${subkey.privkey}')">Show QR</button>
                    <button class="hide-qr-priv" onclick="hideQR(this)">Hide QR</button>
                    <div class="qr-code"></div>    
                </td>
                <td>${subkey.allowed_kinds}</td>
                <td>
                    <button onclick="deleteSubkey('${subkey.pubkey}')" class="button delete">Delete</button>
                </td>
            `;
            subkeyTableBody.appendChild(row);
        });
        updateDeleteSelectedButton();
    }

    function showQR(button, pubkey) {
        const qrContainer = button.nextElementSibling.nextElementSibling;
        qrContainer.innerHTML = '';
        new QRCode(qrContainer, {
            text: pubkey,
            width: 128,
            height: 128
        });
        qrContainer.style.display = 'block';
        button.style.display = 'none';
        button.nextElementSibling.style.display = 'inline-block';
    }

    function hideQR(button) {
        const qrContainer = button.nextElementSibling;
        qrContainer.style.display = 'none';
        button.style.display = 'none';
        button.previousElementSibling.style.display = 'inline-block';
    }

    function updateDeleteSelectedButton() {
        const deleteSelectedButton = document.getElementById('delete-selected');
        const checkedBoxes = document.querySelectorAll('.subkey-checkbox:checked');
        deleteSelectedButton.style.display = checkedBoxes.length > 0 ? 'block' : 'none';
    }

    async function deleteSubkey(pubkey) {
        const token = await getAuthToken('/api/subkey/' + pubkey, 'DELETE');
        const response = await fetch("/api/subkey/" + pubkey, {
            method: 'DELETE',
            headers: {
                'Authorization': 'Nostr ' + token
            }
        });

        if (response.ok) {
            console.log("Deleted subkey:", pubkey);
            loadSubkeys();
        } else {
            alert('Failed to delete subkey');
        }
    }

    async function addSubkey(event) {
        event.preventDefault();
        const form = event.target;
        const formData = new FormData(form);
        let privkey = formData.get('privkey').trim();
        const allowedKinds = formData.get('allowed_kinds').split(',').map(k => k.trim()).join(',');
        
        const subkey = {
            privkey: privkey,
            allowed_kinds: allowedKinds
        };

        const token = await getAuthToken('/api/subkey', 'POST');

        const response = await fetch('/api/subkey', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': 'Nostr ' + token
            },
            body: JSON.stringify(subkey)
        });

        if (response.ok) {
            const result = await response.json();
            console.log("Added subkey with pubkey:", result.pubkey);
            form.reset();
            loadSubkeys();
        } else {
            alert('Failed to add subkey');
        }
    }

    document.addEventListener('DOMContentLoaded', function() {
        document.getElementById('login-button').addEventListener('click', login);
        document.getElementById('add-subkey-form').addEventListener('submit', addSubkey);
        document.getElementById('select-all').addEventListener('change', function() {
            const checkboxes = document.querySelectorAll('.subkey-checkbox');
            checkboxes.forEach(checkbox => checkbox.checked = this.checked);
            updateDeleteSelectedButton();
        });
        document.getElementById('subkey-table-body').addEventListener('change', function(e) {
            if (e.target.classList.contains('subkey-checkbox')) {
                updateDeleteSelectedButton();
            }
        });
        document.getElementById('delete-selected').addEventListener('click', async function() {
            const checkedBoxes = document.querySelectorAll('.subkey-checkbox:checked');
            const pubkeys = Array.from(checkedBoxes).map(checkbox => checkbox.dataset.pubkey);
            
            for (const pubkey of pubkeys) {
                await deleteSubkey(pubkey);
            }
            
            loadSubkeys();
        });
    });
</script>
</body>
</html>
```

