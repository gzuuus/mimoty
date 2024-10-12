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

	config.RelayPrivateKey = nostr.GeneratePrivateKey()
	os.Setenv("ROOT_PRIVATE_KEY", config.RelayPrivateKey)

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

	rootPubkey, _ := nostr.GetPublicKey(config.RelayPrivateKey)
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
