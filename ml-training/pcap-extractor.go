package main

import (
	"encoding/csv"
	"flag"
	"fmt"
	"log"
	"os"

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
		log.Fatal(err)
	}
	defer handle.Close()

	// Reusing your windowing map
	activeWindows := make(map[string]*features.Window)
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	log.Printf("Parsing %s...", filename)

	for packet := range packetSource.Packets() {
		// Extract the DNS layer
		dnsLayer := packet.Layer(layers.LayerTypeDNS)
		if dnsLayer != nil {
			dns, _ := dnsLayer.(*layers.DNS)

			// We only care about queries with questions
			if len(dns.Questions) == 0 {
				continue
			}

			// Extract IP layer for the ClientIP
			clientIP := "0.0.0.0"
			if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
				ip, _ := ipLayer.(*layers.IPv4)
				clientIP = ip.SrcIP.String()
			}

			domain := string(dns.Questions[0].Name)
			rootDomain := features.ExtractRootDomain(domain)
			key := rootDomain + "|" + clientIP

			logEvent := parser.DnsLog{
				Timestamp: packet.Metadata().Timestamp,
				ClientIP:  clientIP,
				Domain:    domain,
				QueryType: dns.Questions[0].Type.String(),
			}

			// Add to window
			if win, exists := activeWindows[key]; exists {
				win.Events = append(win.Events, logEvent)
			} else {
				activeWindows[key] = &features.Window{
					Domain:    rootDomain,
					ClientIP:  clientIP,
					StartedAt: packet.Metadata().Timestamp,
					Events:    []parser.DnsLog{logEvent},
				}
			}
		}
	}

	// Once the PCAP is fully read, flush all windows to the CSV
	writeToCSV(activeWindows, label)
}

func writeToCSV(windows map[string]*features.Window, label int) {
	f, _ := os.OpenFile("dataset.csv", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	defer f.Close()
	writer := csv.NewWriter(f)
	defer writer.Flush()

	for _, win := range windows {
		// Only process windows that have enough data to be meaningful
		if len(win.Events) > 5 {
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
	log.Printf("Successfully appended features to dataset.csv")
}
