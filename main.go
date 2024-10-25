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
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/dgraph-io/ristretto"
	"github.com/fiatjaf/eventstore/sqlite3"
	"github.com/fiatjaf/khatru"
	"github.com/fiatjaf/khatru/policies"
	"github.com/kelseyhightower/envconfig"
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
	// Server config
	Port    string `envconfig:"PORT" default:"3334"`
	LogFile string `envconfig:"LOG_FILE"`
	// FIXME: the configuration is not beign loaded properly
	// Relay metadata
	RelayName        string `envconfig:"RELAY_NAME" required:"true" default:"mimo"`
	RelayPrivateKey  string `envconfig:"ROOT_PRIVATE_KEY" required:"true"`
	RelayDescription string `envconfig:"RELAY_DESCRIPTION"`
	RelayIcon        string `envconfig:"RELAY_ICON"`
	RelayContact     string `envconfig:"RELAY_CONTACT"`
	RelayDomain      string `envconfig:"RELAY_DOMAIN" required:"true"`

	// Database paths
	EventsDBPath  string `envconfig:"EV_DB_PATH" default:"event.db"`
	SubkeysDBPath string `envconfig:"SUBKEYS_DB_PATH" default:"subkeys.db"`

	// Network settings
	RefreshInterval time.Duration `envconfig:"REFRESH_INTERVAL" default:"2h"`
	MaxHops         int           `envconfig:"MAX_HOPS" default:"2"`

	// Computed fields (not from env)
	RelayPubkey string
}

type SubkeyManager struct {
	db          *sql.DB
	cache       *ristretto.Cache
	rootPubkey  string
	rootPrivkey string
}

type Subkey struct {
	Pubkey       string
	Privkey      string
	Name         string
	AllowedKinds []int
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

type ValidationResult struct {
	IsValid      bool
	IsSubkey     bool
	AllowedKinds []int
	Reason       string
}

func LoadConfig() (*Config, error) {
	var cfg Config
	if err := envconfig.Process("", &cfg); err != nil {
		return nil, fmt.Errorf("error processing config: %w", err)
	}

	// Validate and compute derived fields
	pubkey, err := nostr.GetPublicKey(cfg.RelayPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("invalid relay private key: %w", err)
	}
	cfg.RelayPubkey = pubkey

	return &cfg, nil
}

func main() {
	if err := initApp(); err != nil {
		log.Fatalf("Failed to initialize application: %v", err)
	}

	mux := setupHTTPHandlers(relay, &config)

	addr := fmt.Sprintf(":%s", config.Port)
	log.Printf("Starting server on %s", addr)
	server := &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	go RefreshTrustNetwork(context.Background())

	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

func setupHTTPHandlers(relay *khatru.Relay, config *Config) *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept") == "application/nostr+json" {
			w.Header().Set("Content-Type", "application/nostr+json")
			w.Header().Set("Access-Control-Allow-Origin", "*")
			json.NewEncoder(w).Encode(relay.Info)
			return
		}

		if r.URL.Path == "/" && r.Header.Get("Upgrade") != "websocket" {
			http.Redirect(w, r, "/home", http.StatusSeeOther)
			return
		}

		relay.ServeHTTP(w, r)
	})

	mux.HandleFunc("/home", createHomeHandler(config))

	// API routes
	mux.HandleFunc("/api/login", authMiddleware(LoginHandler))
	mux.HandleFunc("/api/subkeys", authMiddleware(GetSubkeysHandler))
	mux.HandleFunc("/api/subkey", authMiddleware(AddSubkeyHandler))
	mux.HandleFunc("/api/subkey/", authMiddleware(handleSubkeyOperations))
	mux.HandleFunc("/api/subkeys/delete", authMiddleware(DeleteMultipleSubkeysHandler))
	mux.HandleFunc("/api/subkey/generate", authMiddleware(GenerateSubkeyHandler))

	return mux
}

func handleSubkeyOperations(w http.ResponseWriter, r *http.Request) {
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
	// Load configuration
	cfg, err := LoadConfig()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}
	config = *cfg // Update global config

	// Initialize databases
	if err := InitDatabases(); err != nil {
		return fmt.Errorf("failed to initialize databases: %w", err)
	}

	// Initialize caches
	if err := initCache(); err != nil {
		return fmt.Errorf("failed to initialize cache: %w", err)
	}

	// Initialize subkey manager
	subkeyMgr, err := NewSubkeyManager(subkeyDB, subkeyCache, config.RelayPrivateKey)
	if err != nil {
		return fmt.Errorf("failed to initialize subkey manager: %w", err)
	}

	// Initialize relay
	relay = initializeRelay(&config)
	setupRelay(relay, subkeyMgr)

	// Initialize templates and other components
	if err := initTemplates(); err != nil {
		return fmt.Errorf("failed to initialize templates: %w", err)
	}

	return nil
}

// func validateConfig(config *Config) error {
// 	if config.RelayPrivateKey == "" {
// 		return fmt.Errorf("ROOT_PRIVATE_KEY not set in environment")
// 	}

// 	if config.RelayDomain == "" {
// 		return fmt.Errorf("RELAY_DOMAIN not set in environment")
// 	}

// 	if config.Port == "" {
// 		config.Port = "3334"
// 	}

// 	var err error
// 	config.RelayPubkey, err = nostr.GetPublicKey(config.RelayPrivateKey)
// 	if err != nil {
// 		return fmt.Errorf("failed to get root public key: %w", err)
// 	}

// 	return nil
// }

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

func setupRelay(relay *khatru.Relay, subkeyMgr *SubkeyManager) {
	relay.StoreEvent = append(relay.StoreEvent, func(ctx context.Context, event *nostr.Event) error {
		if subkeyMgr.IsValidSubkeyEvent(event) {
			resignedEvent, err := subkeyMgr.ResignEvent(event)
			if err != nil {
				return fmt.Errorf("failed to resign event: %w", err)
			}
			event = resignedEvent
		}

		if err := eventDB.SaveEvent(ctx, event); err != nil {
			return fmt.Errorf("failed to save event: %w", err)
		}

		relay.BroadcastEvent(event)
		return nil
	})

	relay.QueryEvents = append(relay.QueryEvents, eventDB.QueryEvents)
	relay.DeleteEvent = append(relay.DeleteEvent, eventDB.DeleteEvent)
	relay.RejectEvent = append(relay.RejectEvent, validateEvent)

	// Add rate limiting and other policies
	relay.RejectFilter = append(relay.RejectFilter,
		policies.NoEmptyFilters,
		policies.NoComplexFilters,
	)

	relay.RejectConnection = append(relay.RejectConnection,
		policies.ConnectionRateLimiter(10, time.Minute*2, 30),
	)

	// Add logging hooks
	relay.OnConnect = append(relay.OnConnect, func(ctx context.Context) {
		log.Printf("New WebSocket connection established")
	})

	relay.OnDisconnect = append(relay.OnDisconnect, func(ctx context.Context) {
		log.Printf("WebSocket connection closed")
	})
}

func initializeRelay(config *Config) *khatru.Relay {
	relay := khatru.NewRelay()

	relay.Info.Name = config.RelayName
	relay.Info.PubKey = config.RelayPubkey
	relay.Info.Icon = config.RelayIcon
	relay.Info.Description = config.RelayDescription
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
	if isValidSubkeyEvent(event) {
		return false, ""
	}

	if _, found := trustNetworkCache.Get(event.PubKey); found {
		return false, ""
	}

	if trustNetworkMap[event.PubKey] {
		trustNetworkCache.Set(event.PubKey, true, 1)
		return false, ""
	}

	return true, "event not allowed: pubkey not in trust network"
}

func isValidSubkeyEvent(event *nostr.Event) bool {
	if cached, found := subkeyCache.Get(event.PubKey); found {
		allowedKinds, ok := cached.([]int)
		if !ok {
			log.Printf("Invalid cache entry type for pubkey %s: %T", event.PubKey, cached)
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

func NewSubkeyManager(db *sql.DB, cache *ristretto.Cache, rootPrivkey string) (*SubkeyManager, error) {
	rootPubkey, err := nostr.GetPublicKey(rootPrivkey)
	if err != nil {
		return nil, fmt.Errorf("invalid root private key: %w", err)
	}

	return &SubkeyManager{
		db:          db,
		cache:       cache,
		rootPubkey:  rootPubkey,
		rootPrivkey: rootPrivkey,
	}, nil
}

func (sm *SubkeyManager) AddSubkey(ctx context.Context, privkey, name, allowedKinds string) (*Subkey, error) {
	pubkey, err := nostr.GetPublicKey(privkey)
	if err != nil {
		return nil, fmt.Errorf("invalid private key: %w", err)
	}

	now := time.Now()
	_, err = sm.db.ExecContext(ctx,
		`INSERT INTO subkeys (pubkey, privkey, name, allowed_kinds, created_at, updated_at) 
		 VALUES (?, ?, ?, ?, ?, ?)`,
		pubkey, privkey, name, allowedKinds, now.Unix(), now.Unix())
	if err != nil {
		return nil, fmt.Errorf("failed to insert subkey: %w", err)
	}

	kinds := parseAllowedKinds(allowedKinds)
	sm.cache.Set(pubkey, kinds, 1)

	return &Subkey{
		Pubkey:       pubkey,
		Privkey:      privkey,
		Name:         name,
		AllowedKinds: kinds,
		CreatedAt:    now,
		UpdatedAt:    now,
	}, nil
}

func (sm *SubkeyManager) IsValidSubkeyEvent(event *nostr.Event) bool {
	if cached, found := sm.cache.Get(event.PubKey); found {
		allowedKinds, ok := cached.([]int)
		if !ok {
			log.Printf("Invalid cache entry type for pubkey %s: %T", event.PubKey, cached)
			return false
		}
		return contains(allowedKinds, event.Kind)
	}

	var allowedKindsStr string
	err := sm.db.QueryRow("SELECT allowed_kinds FROM subkeys WHERE pubkey = ?", event.PubKey).
		Scan(&allowedKindsStr)
	if err != nil {
		if err != sql.ErrNoRows {
			log.Printf("Error querying subkey for pubkey %s: %v", event.PubKey, err)
		}
		return false
	}

	allowedKinds := parseAllowedKinds(allowedKindsStr)
	sm.cache.Set(event.PubKey, allowedKinds, 1)

	return contains(allowedKinds, event.Kind)
}

func (sm *SubkeyManager) ResignEvent(event *nostr.Event) (*nostr.Event, error) {
	resignedEvent := *event
	resignedEvent.PubKey = sm.rootPubkey
	resignedEvent.CreatedAt = nostr.Timestamp(time.Now().Unix())

	if err := resignedEvent.Sign(sm.rootPrivkey); err != nil {
		return nil, fmt.Errorf("failed to sign event: %w", err)
	}

	return &resignedEvent, nil
}
