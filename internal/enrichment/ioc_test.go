package enrichment

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"wiremind/internal/models"
)

// writeTemp writes content to a temp file and returns its path.
func writeTemp(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "ioc-*.txt")
	if err != nil {
		t.Fatalf("create temp: %v", err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatalf("write temp: %v", err)
	}
	f.Close()
	return f.Name()
}

// ---------------------------------------------------------------------------
// LoadFile — file handling
// ---------------------------------------------------------------------------

func TestLoadFile_MissingFile_IsWarningNotError(t *testing.T) {
	m := NewIOCMatcher()
	err := m.LoadFile("/nonexistent/feed.txt", "test", models.IOCTypeIP, models.IOCSeverityHigh)
	if err != nil {
		t.Errorf("missing file should be a warning, not an error: %v", err)
	}
	ips, cidrs, domains, hashes := m.Counts()
	if ips+cidrs+domains+hashes != 0 {
		t.Error("expected no entries after missing file")
	}
}

func TestLoadFile_CommentsAndBlankLines(t *testing.T) {
	content := `# This is a comment
1.2.3.4
# Another comment

5.6.7.8  # inline comment
  9.10.11.12
`
	path := writeTemp(t, content)
	m := NewIOCMatcher()
	if err := m.LoadFile(path, "test", models.IOCTypeIP, models.IOCSeverityLow); err != nil {
		t.Fatalf("LoadFile: %v", err)
	}

	ips, _, _, _ := m.Counts()
	if ips != 3 {
		t.Errorf("expected 3 IPs, got %d", ips)
	}
}

// ---------------------------------------------------------------------------
// MatchIP — exact and CIDR
// ---------------------------------------------------------------------------

func TestMatchIP_ExactHit(t *testing.T) {
	content := "185.220.101.1\n45.33.32.156\n"
	path := writeTemp(t, content)

	m := NewIOCMatcher()
	m.LoadFile(path, "feodo", models.IOCTypeIP, models.IOCSeverityHigh)

	hits := m.MatchIP(net.ParseIP("185.220.101.1"))
	if len(hits) != 1 {
		t.Fatalf("expected 1 hit, got %d", len(hits))
	}
	if hits[0].Source != "feodo" {
		t.Errorf("Source: got %q want %q", hits[0].Source, "feodo")
	}
	if hits[0].Severity != models.IOCSeverityHigh {
		t.Errorf("Severity: got %q want %q", hits[0].Severity, models.IOCSeverityHigh)
	}
	if hits[0].Type != models.IOCTypeIP {
		t.Errorf("Type: got %q want %q", hits[0].Type, models.IOCTypeIP)
	}
}

func TestMatchIP_Miss(t *testing.T) {
	content := "1.2.3.4\n"
	path := writeTemp(t, content)

	m := NewIOCMatcher()
	m.LoadFile(path, "test", models.IOCTypeIP, models.IOCSeverityMedium)

	hits := m.MatchIP(net.ParseIP("9.9.9.9"))
	if len(hits) != 0 {
		t.Errorf("expected 0 hits, got %d", len(hits))
	}
}

func TestMatchIP_CIDR(t *testing.T) {
	content := "198.51.100.0/24\n"
	path := writeTemp(t, content)

	m := NewIOCMatcher()
	m.LoadFile(path, "custom", models.IOCTypeIP, models.IOCSeverityCritical)

	cases := []struct {
		ip   string
		want bool
	}{
		{"198.51.100.1", true},
		{"198.51.100.255", true},
		{"198.51.101.1", false},
		{"10.0.0.1", false},
	}
	for _, c := range cases {
		hits := m.MatchIP(net.ParseIP(c.ip))
		if (len(hits) > 0) != c.want {
			t.Errorf("MatchIP(%s): got hit=%v want %v", c.ip, len(hits) > 0, c.want)
		}
	}
}

func TestMatchIP_InvalidEntriesSkipped(t *testing.T) {
	content := "not-an-ip\n1.2.3.4\nalso-bad/32\n"
	path := writeTemp(t, content)

	m := NewIOCMatcher()
	m.LoadFile(path, "test", models.IOCTypeIP, models.IOCSeverityLow)

	ips, cidrs, _, _ := m.Counts()
	if ips != 1 {
		t.Errorf("expected 1 valid IP, got %d", ips)
	}
	if cidrs != 0 {
		t.Errorf("expected 0 valid CIDRs, got %d", cidrs)
	}
}

// ---------------------------------------------------------------------------
// MatchDomain — case-insensitive, trailing dot stripped
// ---------------------------------------------------------------------------

func TestMatchDomain_Hit(t *testing.T) {
	content := "evil.example.com\nmalware-c2.net\n"
	path := writeTemp(t, content)

	m := NewIOCMatcher()
	m.LoadFile(path, "abuse.ch", models.IOCTypeDomain, models.IOCSeverityHigh)

	hits := m.MatchDomain("evil.example.com")
	if len(hits) != 1 {
		t.Fatalf("expected 1 hit, got %d", len(hits))
	}
}

func TestMatchDomain_CaseInsensitive(t *testing.T) {
	content := "Evil.Example.COM\n"
	path := writeTemp(t, content)

	m := NewIOCMatcher()
	m.LoadFile(path, "test", models.IOCTypeDomain, models.IOCSeverityMedium)

	cases := []string{"evil.example.com", "EVIL.EXAMPLE.COM", "Evil.Example.Com"}
	for _, d := range cases {
		hits := m.MatchDomain(d)
		if len(hits) != 1 {
			t.Errorf("MatchDomain(%q): expected 1 hit, got %d", d, len(hits))
		}
	}
}

func TestMatchDomain_TrailingDotStripped(t *testing.T) {
	content := "c2.example.com\n"
	path := writeTemp(t, content)

	m := NewIOCMatcher()
	m.LoadFile(path, "test", models.IOCTypeDomain, models.IOCSeverityHigh)

	// DNS responses often include a trailing dot
	hits := m.MatchDomain("c2.example.com.")
	if len(hits) != 1 {
		t.Errorf("trailing dot not stripped: expected 1 hit, got %d", len(hits))
	}
}

func TestMatchDomain_Miss(t *testing.T) {
	content := "evil.com\n"
	path := writeTemp(t, content)

	m := NewIOCMatcher()
	m.LoadFile(path, "test", models.IOCTypeDomain, models.IOCSeverityLow)

	hits := m.MatchDomain("safe.com")
	if len(hits) != 0 {
		t.Errorf("expected 0 hits for non-matching domain, got %d", len(hits))
	}
}

// ---------------------------------------------------------------------------
// MatchHash — case-insensitive hex
// ---------------------------------------------------------------------------

func TestMatchHash_Hit(t *testing.T) {
	hash := "d41d8cd98f00b204e9800998ecf8427e"
	content := strings.ToUpper(hash) + "\n"
	path := writeTemp(t, content)

	m := NewIOCMatcher()
	m.LoadFile(path, "custom", models.IOCTypeHash, models.IOCSeverityCritical)

	// match with lowercase
	hits := m.MatchHash(hash)
	if len(hits) != 1 {
		t.Fatalf("expected 1 hit, got %d", len(hits))
	}
	if hits[0].Type != models.IOCTypeHash {
		t.Errorf("Type: got %q want %q", hits[0].Type, models.IOCTypeHash)
	}
}

func TestMatchHash_Miss(t *testing.T) {
	content := "aabbccdd\n"
	path := writeTemp(t, content)

	m := NewIOCMatcher()
	m.LoadFile(path, "test", models.IOCTypeHash, models.IOCSeverityLow)

	hits := m.MatchHash("00112233")
	if len(hits) != 0 {
		t.Errorf("expected 0 hits, got %d", len(hits))
	}
}

// ---------------------------------------------------------------------------
// Multiple sources — hits from both are returned
// ---------------------------------------------------------------------------

func TestMatchIP_MultipleSources(t *testing.T) {
	ip := "192.0.2.1"

	path1 := writeTemp(t, ip+"\n")
	path2 := writeTemp(t, ip+"\n")

	m := NewIOCMatcher()
	m.LoadFile(path1, "source-a", models.IOCTypeIP, models.IOCSeverityHigh)
	m.LoadFile(path2, "source-b", models.IOCTypeIP, models.IOCSeverityCritical)

	hits := m.MatchIP(net.ParseIP(ip))
	if len(hits) != 2 {
		t.Fatalf("expected 2 hits (one per source), got %d", len(hits))
	}

	sources := map[string]bool{}
	for _, h := range hits {
		sources[h.Source] = true
	}
	if !sources["source-a"] || !sources["source-b"] {
		t.Errorf("expected hits from both sources, got: %v", sources)
	}
}

// ---------------------------------------------------------------------------
// Counts — sanity check
// ---------------------------------------------------------------------------

func TestCounts(t *testing.T) {
	dir := t.TempDir()

	ipFile := filepath.Join(dir, "ips.txt")
	os.WriteFile(ipFile, []byte("1.1.1.1\n2.2.2.2\n10.0.0.0/8\n"), 0o644)

	domainFile := filepath.Join(dir, "domains.txt")
	os.WriteFile(domainFile, []byte("evil.com\nbad.net\n"), 0o644)

	m := NewIOCMatcher()
	m.LoadFile(ipFile, "test", models.IOCTypeIP, models.IOCSeverityHigh)
	m.LoadFile(domainFile, "test", models.IOCTypeDomain, models.IOCSeverityMedium)

	ips, cidrs, domains, hashes := m.Counts()
	if ips != 2 {
		t.Errorf("ips: got %d want 2", ips)
	}
	if cidrs != 1 {
		t.Errorf("cidrs: got %d want 1", cidrs)
	}
	if domains != 2 {
		t.Errorf("domains: got %d want 2", domains)
	}
	if hashes != 0 {
		t.Errorf("hashes: got %d want 0", hashes)
	}
}
