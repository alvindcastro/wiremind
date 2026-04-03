package models

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// ThreatContext
// ---------------------------------------------------------------------------

func TestThreatContext_JSONRoundTrip(t *testing.T) {
	ctx := ThreatContext{
		Indicator: "1.2.3.4",
		Geo: &GeoInfo{
			IP:          "1.2.3.4",
			CountryCode: "US",
			CountryName: "United States",
			City:        "Ashburn",
			Latitude:    39.0438,
			Longitude:   -77.4874,
			ASN:         14618,
			ASNOrg:      "AMAZON-AES",
		},
		IOCMatches: []IOCMatch{
			{
				Indicator: "1.2.3.4",
				Type:      IOCTypeIP,
				Source:    "feodo-tracker",
				Severity:  IOCSeverityHigh,
				Tags:      []string{"c2", "botnet"},
			},
		},
		ThreatIntel: []ThreatIntelResult{
			{
				Indicator: "1.2.3.4",
				Source:    "virustotal",
				Malicious: true,
				Score:     42,
				Tags:      []string{"malware"},
			},
		},
		IsMalicious: true,
		ThreatScore: 85,
	}

	b, err := json.Marshal(ctx)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var got ThreatContext
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if got.Indicator != ctx.Indicator {
		t.Errorf("Indicator: got %q want %q", got.Indicator, ctx.Indicator)
	}
	if got.ThreatScore != ctx.ThreatScore {
		t.Errorf("ThreatScore: got %d want %d", got.ThreatScore, ctx.ThreatScore)
	}
	if !got.IsMalicious {
		t.Error("IsMalicious: got false want true")
	}
	if got.Geo == nil {
		t.Fatal("Geo: got nil want non-nil")
	}
	if got.Geo.CountryCode != "US" {
		t.Errorf("Geo.CountryCode: got %q want %q", got.Geo.CountryCode, "US")
	}
	if len(got.IOCMatches) != 1 {
		t.Fatalf("IOCMatches: got %d want 1", len(got.IOCMatches))
	}
	if got.IOCMatches[0].Severity != IOCSeverityHigh {
		t.Errorf("IOCMatch.Severity: got %q want %q", got.IOCMatches[0].Severity, IOCSeverityHigh)
	}
	if len(got.ThreatIntel) != 1 || !got.ThreatIntel[0].Malicious {
		t.Error("ThreatIntel: expected 1 malicious result")
	}
}

// nil pointer fields tagged omitempty must not appear in JSON output.
func TestThreatContext_OmitEmptyNilFields(t *testing.T) {
	ctx := ThreatContext{
		Indicator:   "evil.example.com",
		IsMalicious: false,
		ThreatScore: 0,
	}

	b, err := json.Marshal(ctx)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(b)

	for _, field := range []string{"geo", "ioc_matches", "threat_intel"} {
		if strings.Contains(s, `"`+field+`"`) {
			t.Errorf("field %q should be omitted when nil/empty, but appears in: %s", field, s)
		}
	}
}

// ---------------------------------------------------------------------------
// EnrichedFlow
// ---------------------------------------------------------------------------

func TestEnrichedFlow_JSONRoundTrip(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)

	ef := EnrichedFlow{
		Flow: Flow{
			FlowID:      "10.0.0.1:1234-10.0.0.2:443-TCP",
			Protocol:    "TCP",
			StartTime:   now,
			LastSeen:    now,
			PacketCount: 10,
			ByteCount:   4096,
			State:       FlowStateEstablished,
		},
		FlowHealth: &FlowHealth{
			FlowID:          "10.0.0.1:1234-10.0.0.2:443-TCP",
			Retransmissions: 2,
		},
		EntropyScore:   7.8,
		IsBeacon:       true,
		BeaconInterval: 30.0,
		BeaconJitter:   0.05,
	}

	b, err := json.Marshal(ef)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var got EnrichedFlow
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if got.Flow.FlowID != ef.Flow.FlowID {
		t.Errorf("Flow.FlowID: got %q want %q", got.Flow.FlowID, ef.Flow.FlowID)
	}
	if got.EntropyScore != ef.EntropyScore {
		t.Errorf("EntropyScore: got %f want %f", got.EntropyScore, ef.EntropyScore)
	}
	if !got.IsBeacon {
		t.Error("IsBeacon: got false want true")
	}
	if got.BeaconInterval != ef.BeaconInterval {
		t.Errorf("BeaconInterval: got %f want %f", got.BeaconInterval, ef.BeaconInterval)
	}
	if got.FlowHealth == nil {
		t.Fatal("FlowHealth: got nil want non-nil")
	}
	if got.FlowHealth.Retransmissions != 2 {
		t.Errorf("FlowHealth.Retransmissions: got %d want 2", got.FlowHealth.Retransmissions)
	}
}

func TestEnrichedFlow_OmitEmptyThreatFields(t *testing.T) {
	ef := EnrichedFlow{
		Flow:         Flow{FlowID: "a-b-TCP"},
		EntropyScore: 3.5,
	}

	b, err := json.Marshal(ef)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(b)

	for _, field := range []string{"src_threat", "dst_threat", "flow_health", "beacon_interval_s", "beacon_jitter"} {
		if strings.Contains(s, `"`+field+`"`) {
			t.Errorf("field %q should be omitted when zero/nil, but appears in: %s", field, s)
		}
	}
}

// ---------------------------------------------------------------------------
// Enriched event wrappers
// ---------------------------------------------------------------------------

func TestEnrichedDNSEvent_OmitEmptyDomainThreats(t *testing.T) {
	e := EnrichedDNSEvent{
		Event: DNSEvent{FlowID: "flow1", QueryID: 42},
	}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(b), "domain_threats") {
		t.Errorf("domain_threats should be omitted when empty")
	}
}

func TestEnrichedTLSEvent_OmitEmptySNIThreat(t *testing.T) {
	e := EnrichedTLSEvent{
		Event: TLSEvent{FlowID: "flow1", SNI: "example.com"},
	}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(b), "sni_threat") {
		t.Errorf("sni_threat should be omitted when nil")
	}
}

func TestEnrichedHTTPEvent_OmitEmptyHostThreat(t *testing.T) {
	e := EnrichedHTTPEvent{
		Event: HTTPEvent{FlowID: "flow1", Host: "example.com"},
	}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(b), "host_threat") {
		t.Errorf("host_threat should be omitted when nil")
	}
}

func TestEnrichedICMPEvent_OmitEmptyThreatFields(t *testing.T) {
	e := EnrichedICMPEvent{
		Event: ICMPEvent{FlowID: "flow1", TypeName: "EchoRequest"},
	}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(b)
	for _, field := range []string{"src_threat", "dst_threat"} {
		if strings.Contains(s, `"`+field+`"`) {
			t.Errorf("field %q should be omitted when nil, but appears in: %s", field, s)
		}
	}
}

// ---------------------------------------------------------------------------
// IOC constants
// ---------------------------------------------------------------------------

func TestIOCTypeConstants(t *testing.T) {
	cases := []struct {
		got  IOCType
		want string
	}{
		{IOCTypeIP, "ip"},
		{IOCTypeDomain, "domain"},
		{IOCTypeHash, "hash"},
	}
	for _, c := range cases {
		if string(c.got) != c.want {
			t.Errorf("IOCType: got %q want %q", c.got, c.want)
		}
	}
}

func TestIOCSeverityConstants(t *testing.T) {
	cases := []struct {
		got  IOCSeverity
		want string
	}{
		{IOCSeverityLow, "low"},
		{IOCSeverityMedium, "medium"},
		{IOCSeverityHigh, "high"},
		{IOCSeverityCritical, "critical"},
	}
	for _, c := range cases {
		if string(c.got) != c.want {
			t.Errorf("IOCSeverity: got %q want %q", c.got, c.want)
		}
	}
}
