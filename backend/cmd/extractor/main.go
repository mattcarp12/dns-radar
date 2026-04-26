package main

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"time"

	"github.com/mattcarp12/dns-radar/internal/features"
	"github.com/mattcarp12/dns-radar/internal/parser"
	"github.com/redis/go-redis/v9"
)

var ctx = context.Background()

func main() {
	redisAddr := os.Getenv("REDIS_ADDR")
	if redisAddr == "" {
		redisAddr = "localhost:6379"
	}

	rdb := redis.NewClient(&redis.Options{Addr: redisAddr})

	// Create Consumer Group (ignore error if it already exists)
	_ = rdb.XGroupCreateMkStream(ctx, "stream:dns_events", "extractor_group", "$").Err()

	// In-memory state for our time windows
	// Key: "domain|clientIP"
	activeWindows := make(map[string]*features.Window)

	// Start a ticker to flush windows every 10 seconds
	ticker := time.NewTicker(10 * time.Second)
	go func() {
		for range ticker.C {
			flushWindows(activeWindows)
		}
	}()

	log.Println("Extractor started, waiting for DNS events...")

	for {
		// Read from Redis Stream
		streams, err := rdb.XReadGroup(ctx, &redis.XReadGroupArgs{
			Group:    "extractor_group",
			Consumer: "worker-1",
			Streams:  []string{"stream:dns_events", ">"},
			Count:    100,
			Block:    2 * time.Second,
		}).Result()

		if err != nil && err != redis.Nil {
			log.Printf("Redis error: %v", err)
			time.Sleep(1 * time.Second)
			continue
		}

		for _, stream := range streams {
			for _, msg := range stream.Messages {
				eventJSON := msg.Values["event"].(string)
				var logEvent parser.DnsLog

				// Inside your Extractor's Redis stream loop:
				if err := json.Unmarshal([]byte(eventJSON), &logEvent); err == nil {

					// 1. Get the root domain (e.g. "evil.com" from "abc.evil.com.")
					rootDomain := features.ExtractRootDomain(logEvent.Domain)

					// 2. Build the key using the ROOT domain
					key := rootDomain + "|" + logEvent.ClientIP

					if win, exists := activeWindows[key]; exists {
						win.Events = append(win.Events, logEvent)
					} else {
						activeWindows[key] = &features.Window{
							Domain:    rootDomain, // Pass the root domain to the window
							ClientIP:  logEvent.ClientIP,
							StartedAt: time.Now(),
							Events:    []parser.DnsLog{logEvent},
						}
					}
				}

				// Acknowledge message so it isn't read again
				rdb.XAck(ctx, "stream:dns_events", "extractor_group", msg.ID)
			}
		}
	}
}

func flushWindows(windows map[string]*features.Window) {
	now := time.Now()
	for key, win := range windows {
		// If the window has been open for more than 30 seconds, process it
		if now.Sub(win.StartedAt) > 30*time.Second {
			// Extract features using the pure math functions you wrote
			featureVector := features.Extract(*win)

			// For now, just log it. Later, this is where we call the ML Inference API.
			featureJSON, _ := json.MarshalIndent(featureVector, "", "  ")
			log.Printf("💥 WINDOW CLOSED [%s] 💥\nExtracted Features:\n%s\n", win.Domain, string(featureJSON))

			// Delete the window from memory
			delete(windows, key)
		}
	}
}
