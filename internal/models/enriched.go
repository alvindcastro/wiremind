package models

import "gorm.io/gorm"

// GeoInfo holds geographic and network metadata for an IP address
// looked up via MaxMind GeoLite2.
type GeoInfo struct {
	gorm.Model  `json:"-"`
	IP          string  `gorm:"index" json:"ip"`
	CountryCode string  `json:"country_code"`
	CountryName string  `json:"country_name"`
	City        string  `json:"city"`
	Latitude    float64 `json:"latitude"`
	Longitude   float64 `json:"longitude"`
	ASN         uint    `json:"asn"`
	ASNOrg      string  `json:"asn_org"`
}

// IOCType identifies the kind of indicator of compromise.
type IOCType string

const (
	IOCTypeIP     IOCType = "ip"
	IOCTypeDomain IOCType = "domain"
	IOCTypeHash   IOCType = "hash"
)

// IOCSeverity is the assessed risk level of a matched IOC.
type IOCSeverity string

const (
	IOCSeverityLow      IOCSeverity = "low"
	IOCSeverityMedium   IOCSeverity = "medium"
	IOCSeverityHigh     IOCSeverity = "high"
	IOCSeverityCritical IOCSeverity = "critical"
)

// IOCMatch records a single hit against the local IOC blocklist.
type IOCMatch struct {
	gorm.Model `json:"-"`
	Indicator  string      `gorm:"index" json:"indicator"`
	Type       IOCType     `json:"type"`
	Source     string      `json:"source"` // e.g. "feodo-tracker", "abuse.ch", "custom"
	Severity   IOCSeverity `json:"severity"`
	Tags       []string    `gorm:"serializer:json" json:"tags,omitempty"`
}

// ThreatIntelResult holds a response from an external threat intel API.
type ThreatIntelResult struct {
	gorm.Model     `json:"-"`
	Indicator      string   `gorm:"index" json:"indicator"`
	Source         string   `json:"source"` // "virustotal", "abuseipdb"
	Malicious      bool     `json:"malicious"`
	Score          int      `json:"score"` // e.g. VirusTotal positives count
	Tags           []string `gorm:"serializer:json" json:"tags,omitempty"`
	LastReportedAt string   `json:"last_reported_at,omitempty"` // RFC3339
}

// ThreatContext aggregates all threat intelligence for a single IP or domain.
// It is the common enrichment payload attached to flows and protocol events.
type ThreatContext struct {
	Indicator   string              `json:"indicator"`
	Geo         *GeoInfo            `json:"geo,omitempty"`
	IOCMatches  []IOCMatch          `json:"ioc_matches,omitempty"`
	ThreatIntel []ThreatIntelResult `json:"threat_intel,omitempty"`
	IsMalicious bool                `json:"is_malicious"` // true if any IOC match or threat intel hit
	ThreatScore int                 `json:"threat_score"` // synthesised 0–100 risk score
}

// EnrichedFlow wraps a parsed Flow with threat context, entropy analysis,
// and beacon detection results.
type EnrichedFlow struct {
	gorm.Model     `json:"-"`
	FlowID         string         `gorm:"index;unique" json:"flow_id"`
	Flow           Flow           `gorm:"foreignKey:FlowID;references:FlowID" json:"flow"`
	SrcThreat      *ThreatContext `gorm:"serializer:json" json:"src_threat,omitempty"`
	DstThreat      *ThreatContext `gorm:"serializer:json" json:"dst_threat,omitempty"`
	FlowHealth     *FlowHealth    `gorm:"foreignKey:FlowID;references:FlowID" json:"flow_health,omitempty"`
	EntropyScore   float64        `json:"entropy_score"`               // Shannon entropy of payload (0–8 bits/byte)
	IsBeacon       bool           `json:"is_beacon"`                   // true if C2 heartbeat pattern detected
	BeaconInterval float64        `json:"beacon_interval_s,omitempty"` // mean inter-packet interval in seconds
	BeaconJitter   float64        `json:"beacon_jitter,omitempty"`     // coefficient of variation (stddev/mean)
}

// EnrichedDNSEvent wraps a DNSEvent with threat context on the queried domains.
type EnrichedDNSEvent struct {
	gorm.Model    `json:"-"`
	EventID       uint            `gorm:"index" json:"-"`
	Event         DNSEvent        `gorm:"foreignKey:EventID" json:"event"`
	DomainThreats []ThreatContext `gorm:"serializer:json" json:"domain_threats,omitempty"`
}

// EnrichedTLSEvent wraps a TLSEvent with threat context on the SNI hostname.
type EnrichedTLSEvent struct {
	gorm.Model `json:"-"`
	EventID    uint           `gorm:"index" json:"-"`
	Event      TLSEvent       `gorm:"foreignKey:EventID" json:"event"`
	SNIThreat  *ThreatContext `gorm:"serializer:json" json:"sni_threat,omitempty"`
}

// EnrichedHTTPEvent wraps an HTTPEvent with threat context on the request host.
type EnrichedHTTPEvent struct {
	gorm.Model `json:"-"`
	EventID    uint           `gorm:"index" json:"-"`
	Event      HTTPEvent      `gorm:"foreignKey:EventID" json:"event"`
	HostThreat *ThreatContext `gorm:"serializer:json" json:"host_threat,omitempty"`
}

// EnrichedICMPEvent wraps an ICMPEvent with threat context on the src/dst IPs.
type EnrichedICMPEvent struct {
	gorm.Model `json:"-"`
	EventID    uint           `gorm:"index" json:"-"`
	Event      ICMPEvent      `gorm:"foreignKey:EventID" json:"event"`
	SrcThreat  *ThreatContext `gorm:"serializer:json" json:"src_threat,omitempty"`
	DstThreat  *ThreatContext `gorm:"serializer:json" json:"dst_threat,omitempty"`
}
