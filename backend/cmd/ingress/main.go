package main

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"os"
	"time"

	dnstap "github.com/dnstap/golang-dnstap"
	framestream "github.com/farsightsec/golang-framestream"
	"github.com/mattcarp12/dns-radar/internal/parser"
	"github.com/miekg/dns"
	"github.com/redis/go-redis/v9"
	"google.golang.org/protobuf/proto"
)

var rdb *redis.Client
var ctx = context.Background()

func main() {
	// 1. Connect to Redis (Configure via env vars for Kubernetes)
	redisAddr := os.Getenv("REDIS_ADDR")
	if redisAddr == "" {
		redisAddr = "localhost:6379" // Fallback for local testing
	}

	rdb = redis.NewClient(&redis.Options{
		Addr:     redisAddr,
		Password: "", // Set via Secret in production
		DB:       0,
	})

	// Test the connection
	if err := rdb.Ping(ctx).Err(); err != nil {
		log.Fatalf("Failed to connect to Redis: %v", err)
	}
	log.Println("Successfully connected to Redis broker.")

	// 2. Start the TCP listener for dnstap
	listener, err := net.Listen("tcp", ":6000")
	if err != nil {
		log.Fatalf("Failed to bind to port: %v", err)
	}
	log.Println("Ingress service listening for dnstap on :6000")

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			continue
		}

		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	fsConfig := &framestream.DecoderOptions{
		ContentType:   []byte("protobuf:dnstap.Dnstap"),
		Bidirectional: false,
	}

	decoder, err := framestream.NewDecoder(conn, fsConfig)
	if err != nil {
		log.Printf("Failed to create framestream decoder: %v", err)
		return
	}

	for {
		buf, err := decoder.Decode()
		if err != nil {
			break
		}
		processDnstapPayload(buf)
	}
}

func processDnstapPayload(payload []byte) {
	dt := &dnstap.Dnstap{}
	if err := proto.Unmarshal(payload, dt); err != nil {
		log.Printf("Failed to unmarshal dnstap protobuf: %v", err)
		return
	}

	msg := dt.GetMessage()
	if msg == nil {
		return
	}

	// We only care about CLIENT_QUERY or CLIENT_RESPONSE
	// For this project, CLIENT_QUERY is usually enough, but let's grab the query bytes
	var dnsPayload []byte
	if msg.GetQueryMessage() != nil {
		dnsPayload = msg.GetQueryMessage()
	} else if msg.GetResponseMessage() != nil {
		dnsPayload = msg.GetResponseMessage()
	} else {
		return
	}

	// Parse the raw DNS packet using miekg/dns
	dnsMsg := new(dns.Msg)
	if err := dnsMsg.Unpack(dnsPayload); err != nil {
		log.Printf("Failed to unpack DNS message: %v", err)
		return
	}

	// If there are no questions in the packet, ignore it
	if len(dnsMsg.Question) == 0 {
		return
	}

	question := dnsMsg.Question[0]

	// Construct our clean internal struct
	logEvent := parser.DnsLog{
		Timestamp:   time.Now(), // Or extract msg.GetQueryTimeSec()
		ClientIP:    net.IP(msg.GetQueryAddress()).String(),
		Domain:      question.Name, // e.g., "evil.hacker.com."
		QueryType:   dns.TypeToString[question.Qtype],
		QueryLength: len(dnsPayload),
		Response:    dns.RcodeToString[dnsMsg.Rcode],
	}

	log.Printf("Parsed DNS Log: %s asking for %s (Type: %s)", logEvent.ClientIP, logEvent.Domain, logEvent.QueryType)
	pushToRedis(logEvent)
}

func pushToRedis(logEvent parser.DnsLog) {
	// Marshal the struct to JSON so it's easy for the Extractor to parse
	payloadBytes, err := json.Marshal(logEvent)
	if err != nil {
		log.Printf("Failed to marshal DNS log: %v", err)
		return
	}

	// XADD appends the message to a stream called "stream:dns_events"
	// The "*" tells Redis to auto-generate a unique ID (e.g., 1526985054069-0)
	err = rdb.XAdd(ctx, &redis.XAddArgs{
		Stream: "stream:dns_events",
		Values: map[string]interface{}{
			"event": string(payloadBytes),
		},
	}).Err()

	if err != nil {
		log.Printf("Failed to push to Redis stream: %v", err)
	}
}
