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
