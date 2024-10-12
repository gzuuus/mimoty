package main

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/nbd-wtf/go-nostr"
)

func RefreshTrustNetwork(ctx context.Context) {
	for {
		runTrustNetworkRefresh(ctx)
		time.Sleep(time.Duration(config.RefreshInterval) * time.Hour)
	}
}

func runTrustNetworkRefresh(ctx context.Context) {
	networkByHop := make(map[int]map[string]bool)
	networkByHop[0] = map[string]bool{config.RelayPubkey: true}

	for hop := 0; hop < config.MaxHops; hop++ {
		log.Printf("🌐 Fetching events for hop %d", hop)
		nextHopNetwork := make(map[string]bool)

		pubkeys := make([]string, 0, len(networkByHop[hop]))
		for pubkey := range networkByHop[hop] {
			pubkeys = append(pubkeys, pubkey)
		}

		var mu sync.Mutex
		var wg sync.WaitGroup
		semaphore := make(chan struct{}, 10)

		for _, pubkey := range pubkeys {
			wg.Add(1)
			go func(pk string) {
				defer wg.Done()
				semaphore <- struct{}{}
				defer func() { <-semaphore }()

				contacts := fetchAndStoreEventsForPubkeys(ctx, []string{pk})
				mu.Lock()
				for contact := range contacts {
					nextHopNetwork[contact] = true
				}
				mu.Unlock()
			}(pubkey)
		}

		wg.Wait()
		networkByHop[hop+1] = nextHopNetwork
	}

	// Update the trustNetworkMap
	trustNetworkMap = make(map[string]bool)
	for _, hopNetwork := range networkByHop {
		for pubkey := range hopNetwork {
			trustNetworkMap[pubkey] = true
			trustNetworkCache.Set(pubkey, true, 1)
		}
	}

	log.Printf("🫂 Total network size: %d", len(trustNetworkMap))
}

func getRelaysForPubkey(ctx context.Context, pubkey string) []string {
	filter := nostr.Filter{
		Authors: []string{pubkey},
		Kinds:   []int{nostr.KindRelayListMetadata},
		Limit:   1,
	}

	events, err := relay.QueryEvents[0](ctx, filter)
	if err != nil {
		log.Printf("Error querying relays for pubkey %s: %v", pubkey, err)
		return seedRelays
	}

	event := <-events
	if event == nil {
		return seedRelays
	}

	relays := []string{}
	for _, tag := range event.Tags {
		if tag[0] == "r" && len(tag) > 1 {
			relays = append(relays, tag[1])
		}
	}

	if len(relays) == 0 {
		return seedRelays
	}

	return relays
}

func getFollowListFromDB(ctx context.Context, pubkey string) ([]string, error) {
	filter := nostr.Filter{
		Authors: []string{pubkey},
		Kinds:   []int{nostr.KindFollowList},
		Limit:   1,
	}

	events, err := relay.QueryEvents[0](ctx, filter)
	if err != nil {
		return nil, err
	}

	event := <-events
	if event == nil {
		return nil, nil
	}

	contacts := []string{}
	for _, tag := range event.Tags {
		if tag[0] == "p" && len(tag) > 1 {
			contacts = append(contacts, tag[1])
		}
	}

	return contacts, nil
}

func fetchAndStoreEventsForPubkeys(ctx context.Context, pubkeys []string) map[string]bool {
	contacts := make(map[string]bool)
	timeoutCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, pubkey := range pubkeys {
		wg.Add(1)
		go func(pk string) {
			defer wg.Done()

			// First, try to get the follow list from our database
			dbContacts, err := getFollowListFromDB(timeoutCtx, pk)
			if err == nil && len(dbContacts) > 0 {
				mu.Lock()
				for _, contact := range dbContacts {
					contacts[contact] = true
				}
				mu.Unlock()
			}

			relays := getRelaysForPubkey(timeoutCtx, pk)
			filters := []nostr.Filter{
				{
					Authors: []string{pk},
					Kinds:   []int{nostr.KindFollowList},
					Limit:   2,
				},
				{
					Authors: []string{pk},
					Kinds:   []int{nostr.KindRelayListMetadata},
					Limit:   2,
				},
				{
					Authors: []string{pk},
					Kinds:   []int{nostr.KindProfileMetadata},
					Limit:   2,
				},
			}

			for ev := range pool.SubManyEose(timeoutCtx, relays, filters) {
				if err := storeEvent(ctx, ev.Event); err != nil {
					log.Printf("Failed to store event: %v", err)
				}

				if ev.Kind == nostr.KindFollowList {
					mu.Lock()
					for _, tag := range ev.Tags {
						if tag[0] == "p" && len(tag) > 1 {
							contacts[tag[1]] = true
						}
					}
					mu.Unlock()
				}
			}
		}(pubkey)
	}

	wg.Wait()
	return contacts
}
