package models

import (
	"time"

	"gorm.io/gorm"
)

// Entity represents a persistent identity in the network (Host, User, etc.)
// that can be correlated across multiple flows and events.
type Entity struct {
	gorm.Model `json:"-"`
	EntityID   string    `gorm:"index;unique" json:"entity_id"` // uuid
	Type       string    `gorm:"index" json:"type"`             // "host" | "user" | "external"
	Name       string    `gorm:"index" json:"name"`             // hostname or username
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`

	// Derived from observation
	IPs       []EntityObservation `gorm:"foreignKey:EntityID;references:EntityID" json:"ips"`
	MACs      []EntityObservation `gorm:"foreignKey:EntityID;references:EntityID" json:"macs"`
	Hostnames []EntityObservation `gorm:"foreignKey:EntityID;references:EntityID" json:"hostnames"`
}

// EntityObservation links an attribute (IP, MAC, Hostname) to an Entity with a time range.
type EntityObservation struct {
	gorm.Model `json:"-"`
	EntityID   string    `gorm:"index" json:"entity_id"`
	AttrType   string    `gorm:"index" json:"attr_type"` // "ip" | "mac" | "hostname"
	Value      string    `gorm:"index" json:"value"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	Confidence float64   `json:"confidence"` // 0.0 to 1.0
}
