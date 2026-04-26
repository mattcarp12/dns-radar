package main

import (
	"encoding/csv"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/mattcarp12/dns-radar/internal/features"
	"github.com/mattcarp12/dns-radar/internal/parser"
)

func main() {
	// Define command-line flags
	pcapFile := flag.String("file", "", "Path to the PCAP file")
	label := flag.Int("label", 0, "Label for the data (0 for normal, 1 for tunnel)")
	flag.Parse()

	if *pcapFile == "" {
		log.Fatal("Error: -file argument is required")
	}

	log.Printf("Starting extraction on %s (Label: %d)", *pcapFile, *label)

	// Call your existing processing function
	processPcap(*pcapFile, *label)
}

func processPcap(filename string, label int) {
	handle, err := pcap.OpenOffline(filename)
	if err != nil {
		log.Fatalf("Failed to open pcap: %v", err)
	}
	defer handle.Close()

	activeWindows := make(map[string]*features.Window)
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	// Open the CSV file to stream rows continuously, instead of holding all in memory
	f, err := os.OpenFile("dataset.csv", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Failed to open CSV: %v", err)
	}
	defer f.Close()

	writer := csv.NewWriter(f)
	defer writer.Flush()

	log.Printf("Parsing %s in 30-second tumbling windows...", filename)

	windowDuration := 30 * time.Second
	packetCount := 0

	for packet := range packetSource.Packets() {
		dnsLayer := packet.Layer(layers.LayerTypeDNS)
		if dnsLayer != nil {
			dns, _ := dnsLayer.(*layers.DNS)

			if len(dns.Questions) == 0 {
				continue
			}

			clientIP := "0.0.0.0"
			if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
				ip, _ := ipLayer.(*layers.IPv4)
				clientIP = ip.SrcIP.String()
			}

			domain := string(dns.Questions[0].Name)
			rootDomain := features.ExtractRootDomain(domain)
			key := rootDomain + "|" + clientIP

			// Use the actual time the packet was recorded on the wire
			packetTime := packet.Metadata().Timestamp

			logEvent := parser.DnsLog{
				Timestamp: packetTime,
				ClientIP:  clientIP,
				Domain:    domain,
				QueryType: dns.Questions[0].Type.String(),
			}

			// Define a threshold for how many queries make a "full" window
			maxEventsPerWindow := 50

			if win, exists := activeWindows[key]; exists {
				// HYBRID TRIGGER: Close if 30s have passed OR if we hit 50 queries
				if packetTime.Sub(win.StartedAt) >= windowDuration || len(win.Events) >= maxEventsPerWindow {
					writeSingleWindow(writer, win, label)

					// Start a fresh window
					activeWindows[key] = &features.Window{
						Domain:    rootDomain,
						ClientIP:  clientIP,
						StartedAt: packetTime,
						Events:    []parser.DnsLog{logEvent},
					}
				} else {
					// Still within limits
					win.Events = append(win.Events, logEvent)
				}
			} else {
				// First time seeing this domain/IP combo
				activeWindows[key] = &features.Window{
					Domain:    rootDomain,
					ClientIP:  clientIP,
					StartedAt: packetTime,
					Events:    []parser.DnsLog{logEvent},
				}
			}
			packetCount++
		}
	}

	// Flush whatever is left in memory at the end of the file
	for _, win := range activeWindows {
		writeSingleWindow(writer, win, label)
	}

	log.Printf("Finished processing %d DNS packets from %s", packetCount, filename)
}

func writeSingleWindow(writer *csv.Writer, win *features.Window, label int) {
	// We still only care about windows with enough traffic to form a pattern
	if len(win.Events) >= 2 {
		fv := features.Extract(*win)

		record := []string{
			fv.Domain,
			fmt.Sprintf("%f", fv.ShannonEntropy),
			fmt.Sprintf("%d", fv.MaxSubdomainLen),
			fmt.Sprintf("%f", fv.AvgSubdomainLen),
			fmt.Sprintf("%f", fv.UnigramDeviation),
			fmt.Sprintf("%f", fv.BigramEntropy),
			fmt.Sprintf("%f", fv.NXDomainRatio),
			fmt.Sprintf("%d", fv.UniqueSubdomains),
			fmt.Sprintf("%f", fv.TXTRatio),
			fmt.Sprintf("%f", fv.Burstiness),
			fmt.Sprintf("%d", label),
		}
		writer.Write(record)
	}
}
