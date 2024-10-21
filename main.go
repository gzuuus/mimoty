package main

// mimo relay
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
	"github.com/fiatjaf/eventstore/sqlite3"
	"github.com/fiatjaf/khatru"
	"github.com/fiatjaf/khatru/policies"
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
	Port             string
	RelayName        string
	RelayPubkey      string
	RelayPrivateKey  string
	RelayDescription string
	RelayIcon        string
	RelayContact     string
	RelayDomain      string
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
		Port:             os.Getenv("PORT"),
		RelayName:        os.Getenv("RELAY_NAME"),
		RelayPrivateKey:  os.Getenv("ROOT_PRIVATE_KEY"),
		RelayDescription: os.Getenv("RELAY_DESCRIPTION"),
		RelayIcon:        os.Getenv("RELAY_ICON"),
		RelayContact:     os.Getenv("RELAY_CONTACT"),
		RelayDomain:      os.Getenv("RELAY_DOMAIN"),
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

	mux := setupHTTPHandlers(relay, &config)

	addr := fmt.Sprintf(":%s", config.Port)
	log.Printf("Starting server on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(err)
	}
}

func setupHTTPHandlers(relay *khatru.Relay, config *Config) *http.ServeMux {
	mux := http.NewServeMux()

	// Root handler for WebSocket and NIP-11 info
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" && r.Header.Get("Upgrade") != "websocket" {
			// Redirect to /home for regular HTTP requests
			http.Redirect(w, r, "/home", http.StatusSeeOther)
			return
		}

		// Handle WebSocket connections and NIP-11 info requests
		relay.ServeHTTP(w, r)
	})

	// Separate handler for the home page
	mux.HandleFunc("/home", createHomeHandler(config))

	// API routes
	mux.HandleFunc("/api/login", authMiddleware(LoginHandler))
	mux.HandleFunc("/api/subkeys", authMiddleware(GetSubkeysHandler))
	mux.HandleFunc("/api/subkey", authMiddleware(AddSubkeyHandler))
	mux.HandleFunc("/api/subkey/", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodDelete:
			DeleteSubkeyHandler(w, r)
		case http.MethodPut:
			if strings.HasSuffix(r.URL.Path, "/kinds") {
				UpdateSubkeyKindsHandler(w, r)
			} else if strings.HasSuffix(r.URL.Path, "/name") {
				UpdateSubkeyNameHandler(w, r)
			} else {
				http.NotFound(w, r)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	mux.HandleFunc("/api/subkeys/delete", authMiddleware(DeleteMultipleSubkeysHandler))
	mux.HandleFunc("/api/subkey/generate", authMiddleware(GenerateSubkeyHandler))

	return mux
}

func createHomeHandler(config *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data := struct {
			RelayName        string
			RelayDescription string
			Host             string
		}{
			RelayName:        config.RelayName,
			RelayDescription: config.RelayDescription,
			Host:             r.Host,
		}
		err := templates.ExecuteTemplate(w, "home.html", data)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
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

	if config.RelayDomain == "" {
		return fmt.Errorf("RELAY_DOMAIN not set in environment")
	}

	if config.Port == "" {
		config.Port = "3334"
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
	relay = config.InitializeRelay()
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

	relay.RejectFilter = append(relay.RejectFilter,
		policies.NoEmptyFilters,
		policies.NoComplexFilters,
	)

	relay.RejectConnection = append(relay.RejectConnection,
		policies.ConnectionRateLimiter(10, time.Minute*2, 30),
	)

	relay.OnConnect = append(relay.OnConnect, func(ctx context.Context) {
		log.Printf("New WebSocket connection established")
	})

	relay.OnDisconnect = append(relay.OnDisconnect, func(ctx context.Context) {
		log.Printf("WebSocket connection closed")
	})
}

func (c *Config) InitializeRelay() *khatru.Relay {
	relay := khatru.NewRelay()

	relay.Info.Name = c.RelayName
	relay.Info.PubKey = c.RelayPubkey
	relay.Info.Icon = c.RelayIcon
	relay.Info.Description = c.RelayDescription
	relay.Info.Software = "https://github.com/gzuuus/note-mixer-relay"
	relay.Info.Version = "0.0.1"

	return relay
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

	if err := syncEventWithSubkeys(ctx, event); err != nil {
		log.Printf("Failed to sync event: %v", err)
	}

	relay.BroadcastEvent(event)

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
		switch allowedKinds := cached.(type) {
		case []int:
			return contains(allowedKinds, event.Kind)
		case string:
			parsedKinds := parseAllowedKinds(allowedKinds)
			subkeyCache.Set(event.PubKey, parsedKinds, 1)
			return contains(parsedKinds, event.Kind)
		default:
			log.Printf("Invalid cache entry type for pubkey %s: %T", event.PubKey, cached)
		}
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

	// FIXME: Event id and sig are not valid?
	fmt.Println("Checking id", resignedEvent.CheckID())
	if value, err := resignedEvent.CheckSignature(); err != nil {
		return nil, fmt.Errorf("failed to check sig: %w", err)
	} else if !value {
		return nil, fmt.Errorf("failed to check sig")
	}
	fmt.Println(resignedEvent)
	return &resignedEvent, nil
}

func syncEventWithSubkeys(ctx context.Context, event *nostr.Event) error {
	if event.PubKey != config.RelayPubkey || (event.Kind != 0 && event.Kind != 3 && event.Kind != 10002) {
		return nil
	}

	rows, err := subkeyDB.Query("SELECT pubkey, privkey FROM subkeys")
	if err != nil {
		return fmt.Errorf("failed to fetch subkeys: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var pubkey, privkey string
		if err := rows.Scan(&pubkey, &privkey); err != nil {
			log.Printf("Failed to scan subkey: %v", err)
			continue
		}

		if err := SyncEventWithSubkey(ctx, event, pubkey, privkey); err != nil {
			log.Printf("Failed to sync event for subkey %s: %v", pubkey, err)
		}
	}

	return nil
}

func SyncEventWithSubkey(ctx context.Context, event *nostr.Event, pubkey, privkey string) error {

	switch event.Kind {
	case 0:
		resignedEvent, err := resignEventWithSubkey(event, pubkey, privkey)
		if err != nil {
			return fmt.Errorf("failed to resign event for subkey %s: %w", pubkey, err)
		}
		log.Println("Syncing metadata event for subkey", pubkey)
		if err := eventDB.SaveEvent(ctx, resignedEvent); err != nil {
			return fmt.Errorf("failed to save synced metadata event for subkey %s: %w", pubkey, err)
		}
		go rebroadcastEvent(resignedEvent)
	case 3:
		var filteredTags nostr.Tags
		mimoPubkeyFound := false
		for _, tag := range event.Tags {
			if tag.Key() == "p" {
				if tag.Value() == config.RelayPubkey {
					filteredTags = append(filteredTags, nostr.Tag{"p", config.RelayPubkey})
					mimoPubkeyFound = true
				} else {
					filteredTags = append(filteredTags, nostr.Tag{"p", tag.Value()})
				}
			}
		}

		if !mimoPubkeyFound {
			filteredTags = append(filteredTags, nostr.Tag{"p", config.RelayPubkey})
		}

		event.Tags = filteredTags
		resignedEvent, err := resignEventWithSubkey(event, pubkey, privkey)
		if err != nil {
			return fmt.Errorf("failed to resign event for subkey %s: %w", pubkey, err)
		}
		if err := eventDB.SaveEvent(ctx, resignedEvent); err != nil {
			return fmt.Errorf("failed to save synced metadata event for subkey %s: %w", pubkey, err)
		}
		go rebroadcastEvent(resignedEvent)
	case 10002:
		var filteredTags nostr.Tags
		mimoFound := false

		for _, tag := range event.Tags {
			if tag.Key() == "r" {
				if tag.Value() == config.RelayDomain {
					// Keep mimo relay as is (read and write)
					filteredTags = append(filteredTags, nostr.Tag{"r", config.RelayDomain})
					mimoFound = true
				} else {
					// Set all other relays to read-only
					filteredTags = append(filteredTags, nostr.Tag{"r", tag.Value(), "read"})
				}
			}
		}

		// If the relay wasn't found, add it
		if !mimoFound {
			filteredTags = append(filteredTags, nostr.Tag{"r", config.RelayDomain})
		}

		// Replace the original tags with the filtered tags
		event.Tags = filteredTags
		resignedEvent, err := resignEventWithSubkey(event, pubkey, privkey)
		if err != nil {
			return fmt.Errorf("failed to resign event for subkey %s: %w", pubkey, err)
		}
		if err := eventDB.SaveEvent(ctx, resignedEvent); err != nil {
			return fmt.Errorf("failed to save synced metadata event for subkey %s: %w", pubkey, err)
		}
		go rebroadcastEvent(resignedEvent)
	}

	return nil
}

func rebroadcastEvent(event *nostr.Event) {
	log.Println("Rebroadcasting event", event.Kind)
	for _, url := range seedRelays {
		relay, err := nostr.RelayConnect(context.Background(), url)
		if err != nil {
			log.Printf("Failed to connect to relay %s: %v", url, err)
			continue
		}
		defer relay.Close()

		if err := relay.Publish(context.Background(), *event); err != nil {
			log.Printf("Failed to publish event to relay %s: %v", url, err)
			continue
		}
	}
}
