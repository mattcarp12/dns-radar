package main

import (
	"log"
	"math/rand"
	"net"
	"time"

	dnstap "github.com/dnstap/golang-dnstap"
	framestream "github.com/farsightsec/golang-framestream"
	"github.com/miekg/dns"
	"google.golang.org/protobuf/proto"
)

func main() {
	conn, err := net.Dial("tcp", "localhost:6000")
	if err != nil {
		log.Fatalf("Failed to connect to Ingress: %v", err)
	}
	defer conn.Close()

	fsConfig := &framestream.EncoderOptions{
		ContentType:   []byte("protobuf:dnstap.Dnstap"),
		Bidirectional: false,
	}
	enc, err := framestream.NewEncoder(conn, fsConfig)
	if err != nil {
		log.Fatalf("Failed to create encoder: %v", err)
	}
	defer enc.Close()

	log.Println("Sending normal traffic (google.com)...")
	for i := 0; i < 5; i++ {
		sendFakeDNS(enc, "google.com.", "192.168.1.50")
		time.Sleep(100 * time.Millisecond)
	}

	log.Println("Sending malicious tunnel traffic (high entropy)...")
	for i := 0; i < 20; i++ {
		tunnelDomain := randomString(25) + ".hacker.com."
		sendFakeDNS(enc, tunnelDomain, "192.168.1.100")
		time.Sleep(50 * time.Millisecond)
	}

	log.Println("Finished sending payloads. Keep the extractor running for ~30 seconds to watch the window close!")
}

func sendFakeDNS(enc *framestream.Encoder, domain string, clientIP string) {
	// Create raw DNS packet
	m := new(dns.Msg)
	m.SetQuestion(domain, dns.TypeA)
	dnsBytes, _ := m.Pack()

	// Create Dnstap protobuf
	dtType := dnstap.Dnstap_MESSAGE
	msgType := dnstap.Message_CLIENT_QUERY

	msg := &dnstap.Message{
		Type:         &msgType,
		QueryMessage: dnsBytes,
		QueryAddress: net.ParseIP(clientIP),
	}
	dt := &dnstap.Dnstap{
		Type:    &dtType,
		Message: msg,
	}

	dtBytes, _ := proto.Marshal(dt)

	// Write to Framestream
	if _, err := enc.Write(dtBytes); err != nil {
		log.Printf("Failed to write to framestream: %v", err)
	}
	enc.Flush()
}

func randomString(n int) string {
	var letters = []rune("abcdefghijklmnopqrstuvwxyz1234567890")
	s := make([]rune, n)
	for i := range s {
		s[i] = letters[rand.Intn(len(letters))]
	}
	return string(s)
}
