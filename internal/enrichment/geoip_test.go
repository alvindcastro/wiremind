package enrichment

import (
	"net"
	"os"
	"testing"
)

// ---------------------------------------------------------------------------
// Constructor error cases (no real DB required)
// ---------------------------------------------------------------------------

func TestNewGeoIPEnricher_NoPaths(t *testing.T) {
	_, err := NewGeoIPEnricher("", "")
	if err == nil {
		t.Fatal("expected error when no paths provided, got nil")
	}
}

func TestNewGeoIPEnricher_MissingCityFile(t *testing.T) {
	_, err := NewGeoIPEnricher("/nonexistent/GeoLite2-City.mmdb", "")
	if err == nil {
		t.Fatal("expected error for non-existent city db, got nil")
	}
}

func TestNewGeoIPEnricher_MissingASNFile(t *testing.T) {
	_, err := NewGeoIPEnricher("", "/nonexistent/GeoLite2-ASN.mmdb")
	if err == nil {
		t.Fatal("expected error for non-existent asn db, got nil")
	}
}

// ---------------------------------------------------------------------------
// isPrivateIP — no DB required
// ---------------------------------------------------------------------------

func TestIsPrivateIP(t *testing.T) {
	cases := []struct {
		ip      string
		private bool
	}{
		{"10.0.0.1", true},
		{"10.255.255.255", true},
		{"172.16.0.1", true},
		{"172.31.255.255", true},
		{"192.168.1.100", true},
		{"127.0.0.1", true},
		{"169.254.0.1", true},
		{"::1", true},
		{"fe80::1", true},
		{"0.0.0.0", true},
		// public addresses
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"208.67.222.222", false},
		{"2001:4860:4860::8888", false},
	}

	for _, c := range cases {
		ip := net.ParseIP(c.ip)
		if ip == nil {
			t.Fatalf("invalid test IP: %s", c.ip)
		}
		got := isPrivateIP(ip)
		if got != c.private {
			t.Errorf("isPrivateIP(%s): got %v want %v", c.ip, got, c.private)
		}
	}
}

// ---------------------------------------------------------------------------
// Lookup with private IPs — no DB required
// ---------------------------------------------------------------------------

func TestLookup_PrivateIP_ReturnsStubbedResult(t *testing.T) {
	// We can create an enricher with no real DB by providing a path to
	// any existing file; we only need to test private IP short-circuit,
	// which returns before any DB is consulted.
	//
	// Create a temporary placeholder file so the constructor doesn't error.
	f, err := os.CreateTemp(t.TempDir(), "fake-*.mmdb")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	// Write minimal valid mmdb magic bytes — enough to pass file open,
	// but we will never actually query it for private IPs.
	f.Close()

	// The test relies on isPrivateIP short-circuiting before any DB read.
	// We test isPrivateIP directly above, so here we just verify
	// the Lookup result shape for a private IP.
	privateIPs := []string{"192.168.1.1", "10.0.0.1", "127.0.0.1"}

	for _, addr := range privateIPs {
		ip := net.ParseIP(addr)
		info := (&GeoIPEnricher{}).Lookup(ip) // zero enricher — both DBs nil
		if info == nil {
			t.Fatalf("Lookup(%s): got nil, want GeoInfo", addr)
		}
		if info.IP != addr {
			t.Errorf("Lookup(%s).IP: got %q want %q", addr, info.IP, addr)
		}
		if info.CountryCode != "" {
			t.Errorf("Lookup(%s).CountryCode: got %q want empty for private IP", addr, info.CountryCode)
		}
		if info.ASN != 0 {
			t.Errorf("Lookup(%s).ASN: got %d want 0 for private IP", addr, info.ASN)
		}
	}
}

// ---------------------------------------------------------------------------
// Lookup with real DB — skipped unless MAXMIND_DB_PATH is set
// ---------------------------------------------------------------------------

func TestLookup_PublicIP_WithRealDB(t *testing.T) {
	cityPath := os.Getenv("MAXMIND_DB_PATH")
	if cityPath == "" {
		t.Skip("MAXMIND_DB_PATH not set — skipping live GeoIP lookup test")
	}

	e, err := NewGeoIPEnricher(cityPath, "")
	if err != nil {
		t.Fatalf("NewGeoIPEnricher: %v", err)
	}
	defer e.Close()

	// 8.8.8.8 is a well-known public IP (Google DNS) — MaxMind consistently
	// places it in the United States.
	ip := net.ParseIP("8.8.8.8")
	info := e.Lookup(ip)

	if info == nil {
		t.Fatal("Lookup: got nil")
	}
	if info.IP != "8.8.8.8" {
		t.Errorf("IP: got %q want %q", info.IP, "8.8.8.8")
	}
	if info.CountryCode != "US" {
		t.Errorf("CountryCode: got %q want %q", info.CountryCode, "US")
	}
	if info.CountryName == "" {
		t.Error("CountryName: got empty, want non-empty")
	}
}

func TestLookup_ASN_WithRealDB(t *testing.T) {
	asnPath := os.Getenv("MAXMIND_ASN_DB_PATH")
	if asnPath == "" {
		t.Skip("MAXMIND_ASN_DB_PATH not set — skipping live ASN lookup test")
	}

	e, err := NewGeoIPEnricher("", asnPath)
	if err != nil {
		t.Fatalf("NewGeoIPEnricher: %v", err)
	}
	defer e.Close()

	ip := net.ParseIP("8.8.8.8")
	info := e.Lookup(ip)

	if info.ASN == 0 {
		t.Error("ASN: got 0, want non-zero for public IP")
	}
	if info.ASNOrg == "" {
		t.Error("ASNOrg: got empty, want non-empty")
	}
}
