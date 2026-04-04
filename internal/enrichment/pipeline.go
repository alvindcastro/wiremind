package enrichment

import (
	"net"
	"time"

	"wiremind/config"
	"wiremind/internal/models"
	"wiremind/internal/parser"
)

// Pipeline coordinates all enrichers to transform a ParseResult into
// enriched event slices.
type Pipeline struct {
	cfg         *config.Config
	GeoIP       *GeoIPEnricher
	IOC         *IOCMatcher
	ThreatIntel *ThreatIntelClient
}

// NewPipeline initialises all enrichers based on the provided configuration.
func NewPipeline(cfg *config.Config) (*Pipeline, error) {
	p := &Pipeline{cfg: cfg}

	// 1. GeoIP
	if cfg.GeoIP.CityDBPath != "" || cfg.GeoIP.ASNDBPath != "" {
		gi, err := NewGeoIPEnricher(cfg.GeoIP.CityDBPath, cfg.GeoIP.ASNDBPath)
		if err == nil {
			p.GeoIP = gi
		}
	}

	// 2. IOC Matcher
	p.IOC = NewIOCMatcher()
	for _, src := range cfg.IOC.Sources {
		p.IOC.LoadFile(src.Path, src.Source, models.IOCType(src.Type), models.IOCSeverity(src.Severity))
	}

	// 3. Threat Intel
	timeout := time.Duration(cfg.ThreatIntel.HTTPTimeoutSec) * time.Second
	cacheTTL := time.Duration(cfg.ThreatIntel.CacheTTLMinutes) * time.Minute
	p.ThreatIntel = NewThreatIntelClient(timeout, cacheTTL)

	return p, nil
}

// EnrichedResult holds the final, fully-enriched output of the pipeline.
type EnrichedResult struct {
	Flows []models.EnrichedFlow      `json:"flows"`
	DNS   []models.EnrichedDNSEvent  `json:"dns"`
	TLS   []models.EnrichedTLSEvent  `json:"tls"`
	HTTP  []models.EnrichedHTTPEvent `json:"http"`
	ICMP  []models.EnrichedICMPEvent `json:"icmp"`
}

// Enrich runs all flows and events through the enrichment suite.
func (p *Pipeline) Enrich(res parser.ParseResult) EnrichedResult {
	out := EnrichedResult{}

	// --- 1. Flows (GeoIP + IOC + ThreatIntel + Entropy + Beacon) ---
	entropy := NewEntropyScorer(0)
	beacon := NewBeaconDetector(0, 0, 0)

	// Feed samples collected during parse
	for id, data := range res.Payloads {
		entropy.Update(id, data)
	}
	for id, ts := range res.Timestamps {
		for _, t := range ts {
			beacon.Update(id, t)
		}
	}

	for _, f := range res.Flows {
		ef := models.EnrichedFlow{
			FlowID:       f.FlowID,
			Flow:         f,
			SrcThreat:    p.enrichIndicator(f.SrcIP.String()),
			DstThreat:    p.enrichIndicator(f.DstIP.String()),
			EntropyScore: entropy.Score(f.FlowID),
			IsBeacon:     false,
		}

		br := beacon.Analyze(f.FlowID)
		ef.IsBeacon = br.IsBeacon
		ef.BeaconInterval = br.Interval
		ef.BeaconJitter = br.Jitter

		out.Flows = append(out.Flows, ef)
	}

	// --- 2. DNS (IOC on domains) ---
	for _, e := range res.DNS {
		ee := models.EnrichedDNSEvent{Event: e}
		for _, q := range e.Questions {
			if tc := p.enrichIndicator(q.Name); tc != nil {
				ee.DomainThreats = append(ee.DomainThreats, *tc)
			}
		}
		out.DNS = append(out.DNS, ee)
	}

	// --- 3. TLS (SNI Threat) ---
	for _, e := range res.TLS {
		out.TLS = append(out.TLS, models.EnrichedTLSEvent{
			Event:     e,
			SNIThreat: p.enrichIndicator(e.SNI),
		})
	}

	// --- 4. HTTP (Host Threat) ---
	for _, e := range res.HTTP {
		out.HTTP = append(out.HTTP, models.EnrichedHTTPEvent{
			Event:      e,
			HostThreat: p.enrichIndicator(e.Host),
		})
	}

	// --- 5. ICMP (Src/Dst Threat) ---
	for _, e := range res.ICMP {
		out.ICMP = append(out.ICMP, models.EnrichedICMPEvent{
			Event:     e,
			SrcThreat: p.enrichIndicator(e.SrcIP.String()),
			DstThreat: p.enrichIndicator(e.DstIP.String()),
		})
	}

	return out
}

func (p *Pipeline) enrichIndicator(val string) *models.ThreatContext {
	if val == "" {
		return nil
	}

	tc := &models.ThreatContext{Indicator: val}
	ip := net.ParseIP(val)

	// 1. GeoIP (only for IPs)
	if ip != nil && p.GeoIP != nil {
		tc.Geo = p.GeoIP.Lookup(ip)
	}

	// 2. IOC Matches
	if ip != nil {
		tc.IOCMatches = p.IOC.MatchIP(ip)
	} else {
		tc.IOCMatches = p.IOC.MatchDomain(val)
	}

	// 3. External Threat Intel (for IPs or domains)
	// We only query if the indicator isn't local-only (private IP)
	if ip == nil || !isPrivateIP(ip) {
		tc.ThreatIntel = p.ThreatIntel.Lookup(val)
	}

	// 4. Final Verdict
	tc.IsMalicious = len(tc.IOCMatches) > 0
	for _, ti := range tc.ThreatIntel {
		if ti.Malicious {
			tc.IsMalicious = true
		}
	}

	// Threat Score synthesis (naive placeholder)
	if tc.IsMalicious {
		tc.ThreatScore = 100
	}

	return tc
}

func (p *Pipeline) Close() {
	if p.GeoIP != nil {
		p.GeoIP.Close()
	}
}
