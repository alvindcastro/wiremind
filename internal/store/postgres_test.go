package store

import (
	"net"
	"testing"
	"time"

	"wiremind/internal/enrichment"
	"wiremind/internal/models"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func setupTestDB(t *testing.T) *PostgresStore {
	// Use SQLite in-memory for testing
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("Failed to connect to test db: %v", err)
	}

	store := &PostgresStore{db: db}
	if err := store.AutoMigrate(); err != nil {
		t.Fatalf("Failed to migrate test db: %v", err)
	}

	return store
}

func TestPostgresStore_SaveEnrichedResult(t *testing.T) {
	store := setupTestDB(t)
	defer store.Close()

	now := time.Now()
	res := enrichment.EnrichedResult{
		Flows: []models.EnrichedFlow{
			{
				FlowID: "flow-1",
				Flow: models.Flow{
					FlowID:    "flow-1",
					StartTime: now,
					SrcIP:     net.ParseIP("1.1.1.1"),
					DstIP:     net.ParseIP("2.2.2.2"),
				},
				EntropyScore: 4.5,
				IsBeacon:     true,
			},
		},
		DNS: []models.EnrichedDNSEvent{
			{
				Event: models.DNSEvent{
					FlowID:    "flow-1",
					Timestamp: now,
					QueryID:   123,
					Questions: []models.DNSQuestion{{Name: "test.com", Type: "A"}},
				},
				DomainThreats: []models.ThreatContext{{Indicator: "test.com", IsMalicious: true}},
			},
		},
	}

	err := store.SaveEnrichedResult(res)
	if err != nil {
		t.Errorf("Failed to save enriched result: %v", err)
	}

	// Verify persistence
	flows, err := store.GetFlows(10)
	if err != nil {
		t.Errorf("Failed to retrieve flows: %v", err)
	}
	if len(flows) != 1 {
		t.Errorf("Expected 1 flow, got %d", len(flows))
	}
	if flows[0].FlowID != "flow-1" || flows[0].EntropyScore != 4.5 {
		t.Errorf("Retrieved flow mismatch: %+v", flows[0])
	}

	// Check if the nested core flow was saved
	var count int64
	store.db.Model(&models.Flow{}).Where("flow_id = ?", "flow-1").Count(&count)
	if count != 1 {
		t.Errorf("Core flow was not saved correctly")
	}
}
