// Package features computes all DNS tunneling detection signals from a
// windowed session. Every feature function is pure (no I/O) for testability.
package features

import (
	"math"
	"strings"
	"time"

	"github.com/mattcarp12/dns-radar/internal/parser"
	"golang.org/x/net/publicsuffix"
)

// FeatureVector holds all computed signals for one (domain, client) window.
// These are the raw inputs to every ML model.
type FeatureVector struct {
	// Identity
	Domain      string    `json:"domain"`
	ClientIP    string    `json:"client_ip"`
	WindowStart time.Time `json:"window_start"`

	// === Entropy features ===

	// ShannonEntropy is the entropy of characters across all subdomain labels.
	// Tunneling tools encode binary payloads as base32/base64 subdomains,
	// producing near-maximum entropy (~4.5 bits/char). Legitimate names are
	// lower (~3.0 bits/char).
	ShannonEntropy float64 `json:"shannon_entropy"`

	// MaxSubdomainLen is the longest individual subdomain label.
	// iodine packs ~220 bytes per query using very long labels; legitimate
	// hostnames rarely exceed 20 characters.
	MaxSubdomainLen int `json:"max_subdomain_len"`

	// AvgSubdomainLen is the mean label length across all queries.
	AvgSubdomainLen float64 `json:"avg_subdomain_len"`

	// TotalQueryLen is the mean total FQDN length.
	AvgQueryLen float64 `json:"avg_query_len"`

	// === N-gram distribution ===

	// UnigramDeviation measures how far the character distribution deviates
	// from English text. High deviation = random / encoded payload.
	UnigramDeviation float64 `json:"unigram_deviation"`

	// BigramEntropy is the entropy of 2-character n-grams. Tunneling tools
	// produce near-uniform bigram distributions; natural language has heavy
	// bigram skew (th, he, in, ...).
	BigramEntropy float64 `json:"bigram_entropy"`

	// === Response code signals ===

	// NXDomainRatio = NXDOMAIN count / total queries.
	// DNS tunneling clients probe many random subdomains, generating high
	// NXDOMAIN rates. Legitimate clients rarely hit NXDOMAIN > 5%.
	NXDomainRatio float64 `json:"nxdomain_ratio"`

	// === Query volume / burstiness ===

	// QueryCount is the raw number of DNS queries in this window.
	QueryCount int `json:"query_count"`

	// UniqueSubdomains is the count of distinct subdomain labels queried.
	// Tunneling continuously generates novel subdomains; CDNs reuse a small
	// fixed set.
	UniqueSubdomains int `json:"unique_subdomains"`

	// Burstiness (coefficient of variation of inter-query intervals).
	// Low burstiness (near 0) indicates a machine generating queries at a
	// steady mechanical rate — typical of dnscat2's heartbeat loop.
	Burstiness float64 `json:"burstiness"`

	// === Record type signals ===

	// TXTRatio = TXT queries / total queries.
	// TXT records carry arbitrary text payloads and are a favourite C2 channel.
	TXTRatio float64 `json:"txt_ratio"`

	// MXRatio is elevated in SMTP-as-C2 scenarios.
	MXRatio float64 `json:"mx_ratio"`
}

type Window struct {
	Domain    string
	ClientIP  string
	StartedAt time.Time
	Events    []parser.DnsLog
}

// Extract computes every feature from a completed window.
func Extract(w Window) FeatureVector {
	fv := FeatureVector{
		Domain:      w.Domain,
		ClientIP:    w.ClientIP,
		WindowStart: w.StartedAt,
		QueryCount:  len(w.Events),
	}

	subdomains := make([]string, 0, len(w.Events))
	totalLen := 0
	maxLen := 0
	nxCount := 0
	txtCount := 0
	mxCount := 0
	uniqueSubs := make(map[string]struct{})
	timestamps := make([]float64, 0, len(w.Events))

	// Aggregate all subdomains for entropy / n-gram computation
	var allChars strings.Builder

	for _, ev := range w.Events {
		sub := ExtractSubdomain(ev.Domain, w.Domain)
		subdomains = append(subdomains, sub)
		uniqueSubs[sub] = struct{}{}
		allChars.WriteString(sub)

		l := len(sub)
		totalLen += len(ev.Domain)
		if l > maxLen {
			maxLen = l
		}

		if ev.Response == "NXDOMAIN" {
			nxCount++
		}
		switch strings.ToUpper(ev.QueryType) {
		case "TXT":
			txtCount++
		case "MX":
			mxCount++
		}
		timestamps = append(timestamps, float64(ev.Timestamp.UnixNano()))
	}

	n := float64(len(w.Events))
	fv.MaxSubdomainLen = maxLen
	fv.AvgSubdomainLen = avgLenOf(subdomains)
	fv.AvgQueryLen = float64(totalLen) / n
	fv.NXDomainRatio = float64(nxCount) / n
	fv.UniqueSubdomains = len(uniqueSubs)
	fv.TXTRatio = float64(txtCount) / n
	fv.MXRatio = float64(mxCount) / n

	// Entropy over concatenated subdomain characters
	fv.ShannonEntropy = shannonEntropy(allChars.String())

	// N-gram features
	fv.UnigramDeviation = unigramDeviation(allChars.String())
	fv.BigramEntropy = bigramEntropy(allChars.String())

	// Burstiness from inter-query intervals
	fv.Burstiness = burstiness(timestamps)

	return fv
}

// ── Feature implementations ─────────────────────────────────────────────────

// shannonEntropy computes H(X) = -Σ p(x) log2 p(x) over the characters in s.
// Max for 26-char alphabet ≈ 4.7 bits. Encoded payloads sit near max.
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[rune]int)
	for _, c := range s {
		freq[c]++
	}
	n := float64(len(s))
	var h float64
	for _, cnt := range freq {
		p := float64(cnt) / n
		h -= p * math.Log2(p)
	}
	return h
}

// englishUnigramFreq is the approximate frequency of each letter in English text.
// Source: Relative frequencies of letters in the English language (Wikipedia).
var englishUnigramFreq = map[rune]float64{
	'e': 0.127, 't': 0.091, 'a': 0.082, 'o': 0.075, 'i': 0.070,
	'n': 0.067, 's': 0.063, 'h': 0.061, 'r': 0.060, 'd': 0.043,
	'l': 0.040, 'c': 0.028, 'u': 0.028, 'm': 0.024, 'w': 0.024,
	'f': 0.022, 'g': 0.020, 'y': 0.020, 'p': 0.019, 'b': 0.015,
	'v': 0.010, 'k': 0.008, 'j': 0.002, 'x': 0.002, 'q': 0.001, 'z': 0.001,
}

// unigramDeviation computes the L1 distance between the observed character
// distribution and English text. Values > 0.4 are suspicious.
func unigramDeviation(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[rune]float64)
	for _, c := range strings.ToLower(s) {
		if c >= 'a' && c <= 'z' {
			freq[c]++
		}
	}
	n := float64(len(s))
	var dist float64
	for c := 'a'; c <= 'z'; c++ {
		observed := freq[c] / n
		expected := englishUnigramFreq[c]
		dist += math.Abs(observed - expected)
	}
	return dist
}

// bigramEntropy computes Shannon entropy over 2-character n-grams.
// Natural language bigrams are highly skewed; encoded payloads are near-uniform.
func bigramEntropy(s string) float64 {
	if len(s) < 2 {
		return 0
	}
	freq := make(map[string]int)
	for i := 0; i < len(s)-1; i++ {
		bg := s[i : i+2]
		freq[bg]++
	}
	n := float64(len(s) - 1)
	var h float64
	for _, cnt := range freq {
		p := float64(cnt) / n
		h -= p * math.Log2(p)
	}
	return h
}

// burstiness returns the coefficient of variation (std/mean) of inter-query
// intervals in nanoseconds. Near 0 = mechanical/constant rate (suspicious).
// High values = human / organic traffic.
func burstiness(timestamps []float64) float64 {
	if len(timestamps) < 3 {
		return 1.0 // default: not suspicious
	}
	intervals := make([]float64, len(timestamps)-1)
	for i := 1; i < len(timestamps); i++ {
		intervals[i-1] = timestamps[i] - timestamps[i-1]
	}
	mean := meanOf(intervals)
	if mean == 0 {
		return 0
	}
	variance := 0.0
	for _, v := range intervals {
		diff := v - mean
		variance += diff * diff
	}
	variance /= float64(len(intervals))
	return math.Sqrt(variance) / mean
}

func meanOf(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	sum := 0.0
	for _, x := range xs {
		sum += x
	}
	return sum / float64(len(xs))
}

func avgLenOf(ss []string) float64 {
	if len(ss) == 0 {
		return 0
	}
	total := 0
	for _, s := range ss {
		total += len(s)
	}
	return float64(total) / float64(len(ss))
}

// ExtractRootDomain safely strips trailing dots and uses the official public
// suffix list to find the true registrable domain, even for things like .co.uk.
func ExtractRootDomain(fqdn string) string {
	// CoreDNS leaves trailing dots on absolute domains (e.g., "evil.com."). Strip it.
	cleanFQDN := strings.TrimSuffix(fqdn, ".")

	root, err := publicsuffix.EffectiveTLDPlusOne(cleanFQDN)
	if err != nil {
		// If the domain is completely malformed, fallback to the cleaned string
		return cleanFQDN
	}
	return root
}

// ExtractSubdomain correctly isolates the label the attacker controls.
func ExtractSubdomain(fqdn, rootDomain string) string {
	cleanFQDN := strings.TrimSuffix(fqdn, ".")
	cleanRoot := strings.TrimSuffix(rootDomain, ".")

	if strings.HasSuffix(cleanFQDN, "."+cleanRoot) {
		return strings.TrimSuffix(cleanFQDN, "."+cleanRoot)
	}
	return cleanFQDN
}
