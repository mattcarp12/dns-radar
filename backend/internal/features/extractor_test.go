package features

import (
	"math"
	"testing"
	"time"

	"github.com/mattcarp12/dns-radar/internal/parser"
)

func TestShannonEntropy(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantMin float64
		wantMax float64
	}{
		{"empty", "", 0, 0},
		{"single char", "aaaaaaa", 0, 0.01},
		{"english word", "thethe", 0.5, 2.0},
		// Base32 label (iodine-style) — expect high entropy
		{"base32", "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJ", 4.5, 5.5},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shannonEntropy(tt.input)
			if got < tt.wantMin || got > tt.wantMax {
				t.Errorf("shannonEntropy(%q) = %.3f, want [%.3f, %.3f]",
					tt.input, got, tt.wantMin, tt.wantMax)
			}
		})
	}
}

func TestBurstiness(t *testing.T) {
	// Equal intervals → near-zero burstiness (mechanical)
	mechanical := []float64{0, 1e9, 2e9, 3e9, 4e9, 5e9}
	b := burstiness(mechanical)
	if b > 0.05 {
		t.Errorf("mechanical traffic burstiness = %.4f, want < 0.05", b)
	}

	// Random intervals → high burstiness (organic)
	organic := []float64{0, 1e8, 5e9, 5.1e9, 20e9, 20.5e9}
	b = burstiness(organic)
	if b < 0.5 {
		t.Errorf("organic traffic burstiness = %.4f, want > 0.5", b)
	}
}

func TestUnigramDeviation(t *testing.T) {
	// English text should be close to the reference distribution
	english := "the quick brown fox jumps over the lazy dog"
	eng := unigramDeviation(english)

	// Base32 characters only (A-Z, 2-7) — very different from English
	base32 := "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	b32 := unigramDeviation(base32)

	if eng >= b32 {
		t.Errorf("expected English deviation (%.3f) < base32 deviation (%.3f)", eng, b32)
	}
}

func TestExtractFullWindow(t *testing.T) {
	// Simulate a 60s iodine-style window
	now := time.Now()
	events := make([]parser.DnsLog, 100)
	for i := range events {
		events[i] = parser.DnsLog{
			Timestamp: now.Add(time.Duration(i) * 600 * time.Millisecond), // steady 10q/s
			ClientIP:  "10.0.0.42",
			Domain:    "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDE.example.com",
			QueryType: "A",
			Response:  "NOERROR",
		}
	}
	// Add some NXDOMAIN
	for i := 0; i < 20; i++ {
		events[i].Response = "NXDOMAIN"
	}

	w := Window{
		Domain:    "example.com",
		ClientIP:  "10.0.0.42",
		StartedAt: now,
		Events:    events,
	}

	fv := Extract(w)

	if fv.QueryCount != 100 {
		t.Errorf("QueryCount = %d, want 100", fv.QueryCount)
	}
	if fv.ShannonEntropy < 4.0 {
		t.Errorf("entropy = %.3f, want > 4.0 for iodine labels", fv.ShannonEntropy)
	}
	if math.Abs(fv.NXDomainRatio-0.2) > 0.01 {
		t.Errorf("NXDomainRatio = %.3f, want 0.2", fv.NXDomainRatio)
	}
	if fv.Burstiness > 0.15 {
		t.Errorf("Burstiness = %.4f, want < 0.15 for mechanical traffic", fv.Burstiness)
	}
}

func TestExtractRootDomain(t *testing.T) {
	cases := []struct{ fqdn, want string }{
		{"abc.evil.example.com", "example.com"},
		{"example.com", "example.com"},
		{"a.b.c.d.example.co.uk", "co.uk"}, // simplified heuristic
	}
	for _, c := range cases {
		got := ExtractRootDomain(c.fqdn)
		if got != c.want {
			t.Errorf("extractRootDomain(%q) = %q, want %q", c.fqdn, got, c.want)
		}
	}
}
