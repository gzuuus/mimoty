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

	"github.com/dgraph-io/ristretto"
	"github.com/fasthttp/websocket"
	"github.com/fiatjaf/eventstore/sqlite3"
	"github.com/fiatjaf/khatru"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	_ "github.com/mattn/go-sqlite3"
	"github.com/nbd-wtf/go-nostr"
)

var (
	eventDB  *sqlite3.SQLite3Backend
	subkeyDB *sql.DB
	relay    *khatru.Relay
	// rebroadcastRelays []string
	templates         *template.Template
	pool              *nostr.SimplePool
	config            Config
	trustNetworkMap   = make(map[string]bool)
	seedRelays        []string
	trustNetworkCache *ristretto.Cache
	subkeyCache       *ristretto.Cache
)

type Config struct {
	RelayName        string
	RelayPubkey      string
	RelayPrivateKey  string
	RelayDescription string
	RelayIcon        string
	RelayContact     string
	EventsDBPath     string
	SubkeysDBPath    string
	RefreshInterval  int
	MaxHops          int
}

type ValidationResult struct {
	IsValid      bool
	IsSubkey     bool
	AllowedKinds []int
	Reason       string
}

func LoadConfig() Config {
	return Config{
		RelayName:        os.Getenv("RELAY_NAME"),
		RelayPrivateKey:  os.Getenv("ROOT_PRIVATE_KEY"),
		RelayDescription: os.Getenv("RELAY_DESCRIPTION"),
		RelayIcon:        os.Getenv("RELAY_ICON"),
		RelayContact:     os.Getenv("RELAY_CONTACT"),
		EventsDBPath:     os.Getenv("EV_DB_PATH"),
		SubkeysDBPath:    os.Getenv("SUBKEYS_DB_PATH"),
		RefreshInterval:  getEnvAsInt("REFRESH_INTERVAL_HOURS", 2),
		MaxHops:          getEnvAsInt("MAX_HOPS", 2),
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

	if config.RelayPrivateKey == "" {
		return fmt.Errorf("ROOT_PRIVATE_KEY not set in environment")
	}

	var err error
	config.RelayPubkey, err = nostr.GetPublicKey(config.RelayPrivateKey)
	if err != nil {
		return fmt.Errorf("failed to get root public key: %w", err)
	}

	if config.EventsDBPath == "" {
		config.EventsDBPath = "events.db"
	}

	if config.SubkeysDBPath == "" {
		config.SubkeysDBPath = "subkeys.db"
	}

	if err := initDatabases(); err != nil {
		return fmt.Errorf("failed to initialize databases: %w", err)
	}
	initCache()
	relay = khatru.NewRelay()
	setupRelay()

	seedRelays = []string{
		"wss://nos.lol",
		"wss://nostr.mom",
		"wss://purplepag.es",
		"wss://purplerelay.com",
		"wss://relay.damus.io",
		"wss://relay.nostr.band",
		"wss://relay.snort.social",
		"wss://relay.primal.net",
		"wss://relay.nostr.bg",
		"wss://no.str.cr",
		"wss://nostr21.com",
		"wss://nostrue.com",
		"wss://relay.siamstr.com",
	}

	ctx := context.Background()
	pool = nostr.NewSimplePool(ctx)
	go RefreshTrustNetwork(ctx)

	if err := initTemplates(); err != nil {
		return fmt.Errorf("failed to initialize templates: %w", err)
	}

	return nil
}

func initCache() error {
	var err error
	trustNetworkCache, err = ristretto.NewCache(&ristretto.Config{
		NumCounters: 1e7,
		MaxCost:     1 << 30,
		BufferItems: 64,
	})
	if err != nil {
		return fmt.Errorf("failed to initialize trust network cache: %w", err)
	}

	subkeyCache, err = ristretto.NewCache(&ristretto.Config{
		NumCounters: 1e7,
		MaxCost:     1 << 30,
		BufferItems: 64,
	})
	if err != nil {
		return fmt.Errorf("failed to initialize subkey cache: %w", err)
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

		if event.Kind != nostr.KindHTTPAuth {
			http.Error(w, "Invalid event kind", http.StatusUnauthorized)
			return
		}

		if event.PubKey != config.RelayPubkey {
			http.Error(w, "Unauthorized pubkey", http.StatusUnauthorized)
			return
		}

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

		ok, err := event.CheckSignature()
		if err != nil || !ok {
			http.Error(w, "Invalid signature", http.StatusUnauthorized)
			return
		}

		if time.Since(time.Unix(int64(event.CreatedAt), 0)) > 5*time.Minute {
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
	if isValidSubkeyEvent(event) {
		resignedEvent, err := resignEventWithRoot(event)
		if event.Kind != 0 && event.Kind != 3 && event.Kind != 10002 {
			if err != nil {
				return fmt.Errorf("failed to re-sign event: %w", err)
			}
			event = resignedEvent
		} else {
			// TODO: resign event with root key, handle more robust logic
			// if err := eventDB.SaveEvent(ctx, resignedEvent); err != nil {
			// 	return fmt.Errorf("failed to save resigned event: %w", err)
			// }
		}
	}

	if err := eventDB.SaveEvent(ctx, event); err != nil {
		return fmt.Errorf("failed to save event: %w", err)
	}

	if event.PubKey == config.RelayPubkey && (event.Kind == 0 || event.Kind == 3 || event.Kind == 10002) {
		if err := syncEventToSubkeys(ctx, event); err != nil {
			log.Printf("Failed to sync event: %v", err)
		}
	}

	return nil
}

func validateEvent(ctx context.Context, event *nostr.Event) (bool, string) {
	// Check if it's a valid subkey event
	if isValidSubkeyEvent(event) {
		return false, ""
	}

	// Check if the pubkey is in the trust network cache
	if _, found := trustNetworkCache.Get(event.PubKey); found {
		return false, ""
	}

	// If not in cache, check the trustNetworkMap
	if trustNetworkMap[event.PubKey] {
		// Add to cache for future quick lookups
		trustNetworkCache.Set(event.PubKey, true, 1)
		return false, ""
	}

	return true, "event not allowed: pubkey not in trust network"
}
func isValidSubkeyEvent(event *nostr.Event) bool {
	if cached, found := subkeyCache.Get(event.PubKey); found {
		allowedKinds, ok := cached.([]int)
		if !ok {
			log.Printf("Invalid cache entry for pubkey %s", event.PubKey)
			return false
		}
		return contains(allowedKinds, event.Kind)
	}

	var allowedKindsStr string
	err := subkeyDB.QueryRow("SELECT allowed_kinds FROM subkeys WHERE pubkey = ?", event.PubKey).Scan(&allowedKindsStr)
	if err != nil {
		if err != sql.ErrNoRows {
			log.Printf("Error querying subkey for pubkey %s: %v", event.PubKey, err)
		}
		return false
	}

	allowedKinds := parseAllowedKinds(allowedKindsStr)
	subkeyCache.Set(event.PubKey, allowedKinds, 1)

	return contains(allowedKinds, event.Kind)
}

func parseAllowedKinds(allowedKindsStr string) []int {
	kinds := strings.Split(allowedKindsStr, ",")
	result := make([]int, 0, len(kinds))
	for _, kind := range kinds {
		if k, err := strconv.Atoi(strings.TrimSpace(kind)); err == nil {
			result = append(result, k)
		}
	}
	return result
}

func contains(slice []int, item int) bool {
	for _, v := range slice {
		if v == item {
			return true
		}
	}
	return false
}

func resignEventWithRoot(event *nostr.Event) (*nostr.Event, error) {
	resignedEvent := *event

	resignedEvent.PubKey = config.RelayPubkey
	resignedEvent.CreatedAt = nostr.Timestamp(time.Now().Unix())
	if err := resignedEvent.Sign(config.RelayPrivateKey); err != nil {
		return nil, err
	}
	return &resignedEvent, nil
}

func resignEventWithSubkey(event *nostr.Event, pubkey, privkey string) (*nostr.Event, error) {
	resignedEvent := *event
	resignedEvent.PubKey = pubkey
	resignedEvent.ID = ""
	resignedEvent.Sig = ""
	resignedEvent.CreatedAt = nostr.Timestamp(time.Now().Unix())

	if err := resignedEvent.Sign(privkey); err != nil {
		return nil, fmt.Errorf("failed to sign event: %w", err)
	}

	return &resignedEvent, nil
}

func syncEventToSubkeys(ctx context.Context, event *nostr.Event) error {
	rows, err := subkeyDB.Query("SELECT pubkey, privkey FROM subkeys")
	if err != nil {
		return fmt.Errorf("failed to fetch subkeys: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var pubkey, privkey string
		if err := rows.Scan(&pubkey, &privkey); err != nil {
			return fmt.Errorf("failed to scan subkey: %w", err)
		}

		resignedEvent, err := resignEventWithSubkey(event, pubkey, privkey)
		if err != nil {
			log.Printf("Failed to resign event for subkey %s: %v", pubkey, err)
			continue
		}
		err = eventDB.SaveEvent(ctx, resignedEvent)
		if err != nil {
			log.Printf("Failed to save synced event for subkey %s: %v", pubkey, err)
		}
	}

	return nil
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
