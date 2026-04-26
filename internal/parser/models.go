package parser

import "time"

// DnsLog represents a standard DNS query event
type DnsLog struct {
	Timestamp   time.Time `json:"timestamp"`
	ClientIP    string    `json:"client_ip"`
	Domain      string    `json:"domain"`
	QueryType   string    `json:"query_type"` // e.g., A, TXT, AAAA
	Response    string    `json:"response"`   // e.g., NOERROR, NXDOMAIN
	QueryLength int       `json:"query_length"`
}