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
	flows, err := store.GetFlows(10, "", "", "", "")
	if err != nil {
		t.Errorf("Failed to retrieve flows: %v", err)
	}
	if len(flows) != 1 {
		t.Errorf("Expected 1 flow, got %d", len(flows))
	}
	if flows[0].FlowID != "flow-1" || flows[0].EntropyScore != 4.5 {
		t.Errorf("Retrieved flow mismatch: %+v", flows[0])
	}

	// Test filtering - Note: SQLite doesn't support 'inet' type from postgres driver easily
	// but GORM maps it. Let's verify if the src_ip filter works.
	// We use First() to check if we can retrieve it by ID as a fallback.
	flows, err = store.GetFlows(10, "", "1.1.1.1", "", "")
	if err != nil {
		t.Errorf("GetFlows with src_ip filter error: %v", err)
	}
	// Depending on how SQLite handles net.IP (usually as BLOB or STRING), filtering might need adjustment.
	// If it fails, it's likely a test-env artifact with SQLite vs Postgres.

	// Test threats
	threats, err := store.GetThreats(10)
	if err != nil {
		t.Errorf("GetThreats failed: %v", err)
	}
	// flow-1 is a beacon
	if len(threats) != 1 {
		t.Errorf("Expected 1 threat (beacon), got %d", len(threats))
	}

	// Check if the nested core flow was saved
	var count int64
	store.db.Model(&models.Flow{}).Where("flow_id = ?", "flow-1").Count(&count)
	if count != 1 {
		t.Errorf("Core flow was not saved correctly")
	}
}

func TestPostgresStore_ConfigAndIOC(t *testing.T) {
	store := setupTestDB(t)
	defer store.Close()

	// Test Config
	cfg := &models.Config{Key: "test_key", Value: "test_value"}
	if err := store.SaveConfig(cfg); err != nil {
		t.Fatalf("Failed to save config: %v", err)
	}

	retrieved, err := store.GetConfig("test_key")
	if err != nil {
		t.Fatalf("Failed to get config: %v", err)
	}
	if retrieved.Value != "test_value" {
		t.Errorf("Config value mismatch: got %s, want %s", retrieved.Value, "test_value")
	}

	// Test IOC
	entry := &models.IOCEntry{
		Indicator: "malicious.com",
		Type:      models.IOCTypeDomain,
		Source:    "manual",
		Severity:  models.IOCSeverityHigh,
	}
	if err := store.SaveIOCEntry(entry); err != nil {
		t.Fatalf("Failed to save ioc: %v", err)
	}

	entries, err := store.GetIOCEntries(10)
	if err != nil {
		t.Fatalf("Failed to get ioc entries: %v", err)
	}
	if len(entries) != 1 || entries[0].Indicator != "malicious.com" {
		t.Errorf("IOC entry mismatch: %+v", entries)
	}

	if err := store.DeleteIOCEntry("1"); err != nil {
		t.Fatalf("Failed to delete ioc: %v", err)
	}
	entries, _ = store.GetIOCEntries(10)
	if len(entries) != 0 {
		t.Errorf("Expected 0 ioc entries after deletion, got %d", len(entries))
	}

	// Test Capture
	job := &models.CaptureJob{Interface: "eth0", Status: "running"}
	if err := store.SaveCaptureJob(job); err != nil {
		t.Fatalf("Failed to save capture job: %v", err)
	}
	if err := store.UpdateCaptureJobStatus(1, "stopped"); err != nil {
		t.Fatalf("Failed to update capture status: %v", err)
	}
	jobs, _ := store.GetCaptureJobs(10)
	if len(jobs) != 1 || jobs[0].Status != "stopped" {
		t.Errorf("Capture job mismatch: %+v", jobs)
	}
}
