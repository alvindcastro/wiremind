package enrichment

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"wiremind/internal/models"
)

// ThreatIntelClient interfaces with external APIs (VirusTotal, AbuseIPDB).
// It includes a simple in-memory cache to avoid redundant API calls.
type ThreatIntelClient struct {
	vtKey      string
	abuseIPKey string
	client     *http.Client
	cache      map[string]cacheEntry
	cacheMu    sync.RWMutex
	cacheTTL   time.Duration
}

type cacheEntry struct {
	results []models.ThreatIntelResult
	expiry  time.Time
}

func NewThreatIntelClient(timeout time.Duration, cacheTTL time.Duration) *ThreatIntelClient {
	return &ThreatIntelClient{
		vtKey:      os.Getenv("VIRUSTOTAL_API_KEY"),
		abuseIPKey: os.Getenv("ABUSEIPDB_API_KEY"),
		client:     &http.Client{Timeout: timeout},
		cache:      make(map[string]cacheEntry),
		cacheTTL:   cacheTTL,
	}
}

// Lookup queries all enabled threat intel sources for an indicator (IP or domain).
func (c *ThreatIntelClient) Lookup(indicator string) []models.ThreatIntelResult {
	if indicator == "" {
		return nil
	}

	// 1. Check Cache
	c.cacheMu.RLock()
	entry, ok := c.cache[indicator]
	c.cacheMu.RUnlock()
	if ok && time.Now().Before(entry.expiry) {
		return entry.results
	}

	// 2. Query APIs
	var results []models.ThreatIntelResult
	var wg sync.WaitGroup

	if c.vtKey != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if res, err := c.queryVirusTotal(indicator); err == nil {
				results = append(results, *res)
			}
		}()
	}

	if c.abuseIPKey != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if res, err := c.queryAbuseIPDB(indicator); err == nil {
				results = append(results, *res)
			}
		}()
	}

	wg.Wait()

	// 3. Update Cache
	if len(results) > 0 {
		c.cacheMu.Lock()
		c.cache[indicator] = cacheEntry{
			results: results,
			expiry:  time.Now().Add(c.cacheTTL),
		}
		c.cacheMu.Unlock()
	}

	return results
}

func (c *ThreatIntelClient) queryVirusTotal(indicator string) (*models.ThreatIntelResult, error) {
	url := fmt.Sprintf("https://www.virustotal.com/api/v3/ip_addresses/%s", indicator)
	// VT v3 uses the same endpoint for domains if we detect it's not an IP,
	// but for simplicity this implementation assumes IP.

	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("x-apikey", c.vtKey)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("vt: status %d", resp.StatusCode)
	}

	var data struct {
		Data struct {
			Attributes struct {
				LastAnalysisStats struct {
					Malicious int `json:"malicious"`
				} `json:"last_analysis_stats"`
				Tags []string `json:"tags"`
			} `json:"attributes"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}

	return &models.ThreatIntelResult{
		Indicator: indicator,
		Source:    "virustotal",
		Malicious: data.Data.Attributes.LastAnalysisStats.Malicious > 0,
		Score:     data.Data.Attributes.LastAnalysisStats.Malicious,
		Tags:      data.Data.Attributes.Tags,
	}, nil
}

func (c *ThreatIntelClient) queryAbuseIPDB(indicator string) (*models.ThreatIntelResult, error) {
	url := fmt.Sprintf("https://api.abuseipdb.com/api/v2/check?ipAddress=%s", indicator)

	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Key", c.abuseIPKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("abuseipdb: status %d", resp.StatusCode)
	}

	var data struct {
		Data struct {
			AbuseConfidenceScore int `json:"abuseConfidenceScore"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}

	return &models.ThreatIntelResult{
		Indicator: indicator,
		Source:    "abuseipdb",
		Malicious: data.Data.AbuseConfidenceScore > 50,
		Score:     data.Data.AbuseConfidenceScore,
	}, nil
}
