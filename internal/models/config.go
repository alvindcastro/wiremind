package models

import "gorm.io/gorm"

// Config represents a dynamic runtime configuration setting.
type Config struct {
	gorm.Model
	Key   string `gorm:"uniqueIndex" json:"key"`
	Value string `json:"value"`
}

// IOCEntry represents a persistent indicator of compromise.
type IOCEntry struct {
	gorm.Model
	Indicator string      `gorm:"index" json:"indicator"`
	Type      IOCType     `json:"type"`     // ip, domain, hash
	Source    string      `json:"source"`   // e.g. "custom", "manual"
	Severity  IOCSeverity `json:"severity"` // low, medium, high, critical
	Tags      []string    `gorm:"serializer:json" json:"tags,omitempty"`
}

// CaptureJob represents a request to start a live packet capture.
type CaptureJob struct {
	gorm.Model
	Interface string `json:"interface"`
	Filter    string `json:"filter"`
	Status    string `json:"status"` // running, stopped
}
