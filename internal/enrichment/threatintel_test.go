package enrichment

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"wiremind/internal/models"
)

func TestThreatIntelLookup(t *testing.T) {
	// 1. Mock VirusTotal API
	vtServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-apikey") != "test-vt-key" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		resp := map[string]interface{}{
			"data": map[string]interface{}{
				"attributes": map[string]interface{}{
					"last_analysis_stats": map[string]int{"malicious": 5},
					"tags":                []string{"malware", "phishing"},
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer vtServer.Close()

	// 2. Mock AbuseIPDB API
	abuseServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Key") != "test-abuse-key" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		resp := map[string]interface{}{
			"data": map[string]interface{}{
				"abuseConfidenceScore": 75,
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer abuseServer.Close()

	client := NewThreatIntelClient(2*time.Second, 1*time.Minute)
	client.vtKey = "test-vt-key"
	client.abuseIPKey = "test-abuse-key"
	client.vtBaseURL = vtServer.URL
	client.abuseBaseURL = abuseServer.URL

	t.Run("Empty Indicator", func(t *testing.T) {
		res := client.Lookup("")
		if res != nil {
			t.Errorf("Expected nil for empty indicator, got %v", res)
		}
	})

	t.Run("Full Lookup", func(t *testing.T) {
		indicator := "1.2.3.4"
		res := client.Lookup(indicator)

		if len(res) != 2 {
			t.Fatalf("Expected 2 results, got %d", len(res))
		}

		foundVT := false
		foundAbuse := false
		for _, r := range res {
			if r.Source == "virustotal" {
				foundVT = true
				if !r.Malicious || r.Score != 5 {
					t.Errorf("Unexpected VT result: %+v", r)
				}
			}
			if r.Source == "abuseipdb" {
				foundAbuse = true
				if !r.Malicious || r.Score != 75 {
					t.Errorf("Unexpected AbuseIPDB result: %+v", r)
				}
			}
		}
		if !foundVT || !foundAbuse {
			t.Errorf("Missing expected sources. VT: %v, Abuse: %v", foundVT, foundAbuse)
		}
	})

	t.Run("Cache Logic", func(t *testing.T) {
		indicator := "cached.com"
		mockResults := []models.ThreatIntelResult{
			{Indicator: indicator, Source: "test", Malicious: true},
		}

		client.cacheMu.Lock()
		client.cache[indicator] = cacheEntry{
			results: mockResults,
			expiry:  time.Now().Add(1 * time.Minute),
		}
		client.cacheMu.Unlock()

		res := client.Lookup(indicator)
		if len(res) != 1 || res[0].Source != "test" {
			t.Errorf("Expected cached result, got %v", res)
		}
	})
}
