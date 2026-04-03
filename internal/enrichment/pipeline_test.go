package enrichment

import (
	"net"
	"testing"
	"time"

	"wiremind/config"
	"wiremind/internal/models"
	"wiremind/internal/parser"
)

func TestPipelineEnrich(t *testing.T) {
	cfg := &config.Config{}
	// Leave GeoIP empty to skip it
	// IOC and ThreatIntel will be initialized but empty/default

	p, err := NewPipeline(cfg)
	if err != nil {
		t.Fatalf("Failed to create pipeline: %v", err)
	}

	now := time.Now()
	res := parser.ParseResult{
		Flows: []models.Flow{
			{
				FlowID:    "test-flow",
				SrcIP:     net.ParseIP("192.168.1.1"),
				DstIP:     net.ParseIP("8.8.8.8"),
				StartTime: now,
			},
		},
		DNS: []models.DNSEvent{
			{
				FlowID:    "test-flow",
				Timestamp: now,
				Questions: []models.DNSQuestion{
					{Name: "malicious.com", Type: "A"},
				},
			},
		},
		Payloads: map[string][]byte{
			"test-flow": []byte("some random data for entropy"),
		},
	}

	enriched := p.Enrich(res)

	if len(enriched.Flows) != 1 {
		t.Errorf("Expected 1 enriched flow, got %d", len(enriched.Flows))
	}

	ef := enriched.Flows[0]
	if ef.Flow.FlowID != "test-flow" {
		t.Errorf("Flow ID mismatch: %s", ef.Flow.FlowID)
	}

	// Entropy should be calculated
	if ef.EntropyScore == 0 {
		t.Errorf("Entropy score should not be 0")
	}

	if len(enriched.DNS) != 1 {
		t.Errorf("Expected 1 enriched DNS event, got %d", len(enriched.DNS))
	}

	// Test indicator enrichment logic via manual IOC addition
	p.ioc.AddMatch("malicious.com", "test-source", models.IOCTypeDomain, models.IOCSeverityHigh)

	enriched2 := p.Enrich(res)
	foundMalicious := false
	for _, de := range enriched2.DNS {
		for _, dt := range de.DomainThreats {
			if dt.Indicator == "malicious.com" && dt.IsMalicious {
				foundMalicious = true
			}
		}
	}
	if !foundMalicious {
		t.Errorf("DNS domain 'malicious.com' was not flagged as malicious")
	}
}
