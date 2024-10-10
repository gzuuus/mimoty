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
	"strconv"
	"strings"
	"time"

	"github.com/fasthttp/websocket"
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
	pool          *nostr.SimplePool
	config        Config
)

type Config struct {
	RelayName        string
	RelayPubkey      string
	RelayPrivateKey  string
	RelayDescription string
	RelayIcon        string
	RelayContact     string
	DBPath           string
	RefreshInterval  int
}

func LoadConfig() Config {
	return Config{
		RelayName:        os.Getenv("RELAY_NAME"),
		RelayPubkey:      os.Getenv("RELAY_PUBKEY"),
		RelayPrivateKey:  os.Getenv("ROOT_PRIVATE_KEY"),
		RelayDescription: os.Getenv("RELAY_DESCRIPTION"),
		RelayIcon:        os.Getenv("RELAY_ICON"),
		RelayContact:     os.Getenv("RELAY_CONTACT"),
		DBPath:           os.Getenv("DB_PATH"),
		RefreshInterval:  getEnvAsInt("REFRESH_INTERVAL_HOURS", 3),
	}
}

func getEnvAsInt(key string, defaultVal int) int {
	if value, exists := os.LookupEnv(key); exists {
		if intVal, err := strconv.Atoi(value); err == nil {
			return intVal
		}
	}
	return defaultVal
}

func main() {
	if err := initApp(); err != nil {
		log.Fatalf("Failed to initialize application: %v", err)
	}

	r := setupRoutes()

	go refreshRootKeyEvents(context.Background(), relay)
	go fetchRootKeyEvents(context.Background(), relay)

	log.Println("Starting server on :3334")
	if err := http.ListenAndServe(":3334", r); err != nil {
		log.Fatal(err)
	}
}

func setupRoutes() *mux.Router {
	r := mux.NewRouter()
	r.HandleFunc("/", rootHandler).Methods("GET")
	r.HandleFunc("/api/login", authMiddleware(LoginHandler)).Methods("POST")
	r.HandleFunc("/api/subkeys", authMiddleware(GetSubkeysHandler)).Methods("GET")
	r.HandleFunc("/api/subkey", authMiddleware(AddSubkeyHandler)).Methods("POST")
	r.HandleFunc("/api/subkey/{pubkey}", authMiddleware(DeleteSubkeyHandler)).Methods("DELETE")
	r.HandleFunc("/api/subkeys/delete", authMiddleware(DeleteMultipleSubkeysHandler)).Methods("POST")
	r.HandleFunc("/api/subkey/{pubkey}/kinds", authMiddleware(UpdateSubkeyKindsHandler)).Methods("PUT")
	r.HandleFunc("/api/subkey/{pubkey}/name", authMiddleware(UpdateSubkeyNameHandler)).Methods("PUT")
	r.HandleFunc("/api/subkey/generate", authMiddleware(GenerateSubkeyHandler)).Methods("POST")

	return r
}
func rootHandler(w http.ResponseWriter, r *http.Request) {
	if websocket.IsWebSocketUpgrade(r) {
		relay.ServeHTTP(w, r)
	} else {
		homeHandler(w, r)
	}
}

func initApp() error {
	if err := godotenv.Load(); err != nil {
		return fmt.Errorf("error loading .env file: %w", err)
	}

	config = LoadConfig()

	rootPrivateKey = config.RelayPrivateKey
	if rootPrivateKey == "" {
		return fmt.Errorf("ROOT_PRIVATE_KEY not set in environment")
	}

	var err error
	rootPublicKey, err = nostr.GetPublicKey(rootPrivateKey)
	if err != nil {
		return fmt.Errorf("failed to get root public key: %w", err)
	}

	if err := initDatabases(); err != nil {
		return fmt.Errorf("failed to initialize databases: %w", err)
	}

	relay = khatru.NewRelay()
	setupRelay()

	ctx := context.Background()
	pool = nostr.NewSimplePool(ctx)

	if err := initTemplates(); err != nil {
		return fmt.Errorf("failed to initialize templates: %w", err)
	}

	return nil
}

func refreshRootKeyEvents(ctx context.Context, relay *khatru.Relay) {
	ticker := time.NewTicker(time.Duration(config.RefreshInterval) * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			fetchRootKeyEvents(ctx, relay)
		case <-ctx.Done():
			return
		}
	}
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

func fetchRootKeyEvents(ctx context.Context, relay *khatru.Relay) {
	rootPubkey := config.RelayPubkey
	seedRelay := "wss://relay.nostr.band"

	filters := []nostr.Filter{{
		Authors: []string{rootPubkey},
		Kinds:   []int{nostr.KindProfileMetadata, nostr.KindFollowList, 10002}, // 0, 3, and 10002
	}}

	log.Println("Fetching root key events")
	events := fetchEvents(ctx, seedRelay, filters)

	for _, ev := range events {
		processAndPublishEvent(ctx, relay, ev)
	}
	log.Printf("Fetched and processed %d events", len(events))
}

func fetchEvents(ctx context.Context, relayURL string, filters []nostr.Filter) []*nostr.Event {
	timeout, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	events := make([]*nostr.Event, 0)
	for ev := range pool.SubManyEose(timeout, []string{relayURL}, filters) {
		events = append(events, ev.Event)
	}
	return events
}

func processAndPublishEvent(ctx context.Context, relay *khatru.Relay, ev *nostr.Event) {
	err := eventDB.SaveEvent(ctx, ev)
	if err != nil {
		log.Printf("Error publishing event %s: %v", ev.ID, err)
		return
	}

	relay.BroadcastEvent(ev)

	switch ev.Kind {
	case nostr.KindProfileMetadata:
		log.Printf("Processed profile metadata")
	case nostr.KindFollowList:
		log.Printf("Processed contact list")
	case 10002:
		log.Printf("Processed relay list metadata")
	}
}
