package enrichment

import (
	"bufio"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"

	"wiremind/internal/models"
)

// IOCMatcher matches IPs, domains, and file hashes against a set of loaded
// blocklists. All lists are held in memory for O(1) exact lookups.
// IP blocklists may also contain CIDR ranges, which are checked linearly
// (there are typically few of them).
//
// Load one or more blocklist files with LoadFile, then call MatchIP,
// MatchDomain, or MatchHash per indicator.
type IOCMatcher struct {
	ips     map[string][]models.IOCMatch // key: normalised IP string
	cidrs   []cidrEntry                  // CIDR range entries (uncommon but supported)
	domains map[string][]models.IOCMatch // key: lowercase domain
	hashes  map[string][]models.IOCMatch // key: lowercase hex hash
}

type cidrEntry struct {
	network *net.IPNet
	match   models.IOCMatch
}

// NewIOCMatcher returns an empty matcher ready for LoadFile calls.
func NewIOCMatcher() *IOCMatcher {
	return &IOCMatcher{
		ips:     make(map[string][]models.IOCMatch),
		domains: make(map[string][]models.IOCMatch),
		hashes:  make(map[string][]models.IOCMatch),
	}
}

// LoadFile reads a flat blocklist file and registers every indicator.
//
// File format:
//   - One indicator per line (IP, CIDR, domain, or hash)
//   - Lines starting with '#' are comments and are ignored
//   - Blank lines are ignored
//   - Inline comments (# …) after an indicator are stripped
//
// iocType must be one of models.IOCTypeIP, IOCTypeDomain, IOCTypeHash.
// severity must be one of the models.IOCSeverity constants.
//
// Missing files are logged as warnings but do not return an error — the
// operator may not have downloaded every feed yet.
func (m *IOCMatcher) LoadFile(path, source string, iocType models.IOCType, severity models.IOCSeverity) error {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			slog.Warn("ioc blocklist file not found, skipping", "path", path)
			return nil
		}
		return fmt.Errorf("ioc: open %s: %w", path, err)
	}
	defer f.Close()

	var count int
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// strip inline comments
		if idx := strings.Index(line, "#"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		if line == "" {
			continue
		}

		entry := models.IOCMatch{
			Indicator: line,
			Type:      iocType,
			Source:    source,
			Severity:  severity,
		}

		switch iocType {
		case models.IOCTypeIP:
			m.addIP(line, entry)
		case models.IOCTypeDomain:
			m.addDomain(line, entry)
		case models.IOCTypeHash:
			m.addHash(line, entry)
		}
		count++
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("ioc: scan %s: %w", path, err)
	}

	slog.Info("ioc blocklist loaded", "path", path, "source", source, "type", iocType, "count", count)
	return nil
}

// addIP registers a single IP or CIDR entry.
func (m *IOCMatcher) addIP(raw string, entry models.IOCMatch) {
	if strings.Contains(raw, "/") {
		// CIDR notation
		_, network, err := net.ParseCIDR(raw)
		if err != nil {
			slog.Debug("ioc: invalid CIDR, skipping", "value", raw, "err", err)
			return
		}
		m.cidrs = append(m.cidrs, cidrEntry{network: network, match: entry})
		return
	}

	ip := net.ParseIP(raw)
	if ip == nil {
		slog.Debug("ioc: invalid IP, skipping", "value", raw)
		return
	}
	key := ip.String()
	m.ips[key] = append(m.ips[key], entry)
}

func (m *IOCMatcher) addDomain(raw string, entry models.IOCMatch) {
	key := strings.ToLower(strings.TrimSuffix(raw, ".")) // strip trailing dot
	entry.Indicator = key
	m.domains[key] = append(m.domains[key], entry)
}

func (m *IOCMatcher) addHash(raw string, entry models.IOCMatch) {
	key := strings.ToLower(raw)
	entry.Indicator = key
	m.hashes[key] = append(m.hashes[key], entry)
}

// AddMatch is a helper for manual injection of indicators (useful for testing).
func (m *IOCMatcher) AddMatch(indicator, source string, iocType models.IOCType, severity models.IOCSeverity) {
	entry := models.IOCMatch{
		Indicator: indicator,
		Type:      iocType,
		Source:    source,
		Severity:  severity,
	}
	switch iocType {
	case models.IOCTypeIP:
		m.addIP(indicator, entry)
	case models.IOCTypeDomain:
		m.addDomain(indicator, entry)
	case models.IOCTypeHash:
		m.addHash(indicator, entry)
	}
}

// MatchIP returns all IOCMatch entries for ip. Checks exact matches first,
// then CIDR ranges. Returns nil if no match is found.
func (m *IOCMatcher) MatchIP(ip net.IP) []models.IOCMatch {
	var hits []models.IOCMatch

	if exact, ok := m.ips[ip.String()]; ok {
		hits = append(hits, exact...)
	}

	for _, c := range m.cidrs {
		if c.network.Contains(ip) {
			hits = append(hits, c.match)
		}
	}

	return hits
}

// MatchDomain returns all IOCMatch entries for domain (case-insensitive,
// trailing dot stripped). Returns nil if no match is found.
func (m *IOCMatcher) MatchDomain(domain string) []models.IOCMatch {
	key := strings.ToLower(strings.TrimSuffix(domain, "."))
	return m.domains[key]
}

// MatchHash returns all IOCMatch entries for hash (case-insensitive hex).
// Returns nil if no match is found.
func (m *IOCMatcher) MatchHash(hash string) []models.IOCMatch {
	return m.hashes[strings.ToLower(hash)]
}

// Counts returns the number of loaded indicators per type.
func (m *IOCMatcher) Counts() (ips, cidrs, domains, hashes int) {
	return len(m.ips), len(m.cidrs), len(m.domains), len(m.hashes)
}
