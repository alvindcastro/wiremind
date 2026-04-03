package store

import (
	"fmt"
	"time"

	"wiremind/config"
	"wiremind/internal/enrichment"
	"wiremind/internal/models"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// PostgresStore handles database persistence for forensics results.
type PostgresStore struct {
	db *gorm.DB
}

// NewPostgresStore creates a new PostgreSQL store and runs migrations.
func NewPostgresStore(cfg config.PostgresConfig) (*PostgresStore, error) {
	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%d sslmode=%s TimeZone=UTC",
		cfg.Host, cfg.User, cfg.Password, cfg.DBName, cfg.Port, cfg.SSLMode)

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return nil, fmt.Errorf("postgres: connect: %w", err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, err
	}
	sqlDB.SetMaxIdleConns(10)
	sqlDB.SetMaxOpenConns(100)
	sqlDB.SetConnMaxLifetime(time.Hour)

	store := &PostgresStore{db: db}
	if err := store.AutoMigrate(); err != nil {
		return nil, fmt.Errorf("postgres: migrate: %w", err)
	}

	return store, nil
}

// AutoMigrate ensures all tables exist and match the GORM models.
func (s *PostgresStore) AutoMigrate() error {
	return s.db.AutoMigrate(
		&models.Flow{},
		&models.FlowHealth{},
		&models.DNSEvent{},
		&models.HTTPEvent{},
		&models.TLSEvent{},
		&models.ICMPEvent{},
		&models.EnrichedFlow{},
		&models.EnrichedDNSEvent{},
		&models.EnrichedHTTPEvent{},
		&models.EnrichedTLSEvent{},
		&models.EnrichedICMPEvent{},
	)
}

// SaveEnrichedResult persists a batch of enriched forensics data.
func (s *PostgresStore) SaveEnrichedResult(res enrichment.EnrichedResult) error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		// 1. Save Flows (core and enriched)
		for _, ef := range res.Flows {
			// Save core flow first (EnrichedFlow refers to it)
			if err := tx.Save(&ef.Flow).Error; err != nil {
				return err
			}
			if err := tx.Save(&ef).Error; err != nil {
				return err
			}
			if ef.FlowHealth != nil {
				if err := tx.Save(ef.FlowHealth).Error; err != nil {
					return err
				}
			}
		}

		// 2. Save Events
		for _, e := range res.DNS {
			if err := tx.Save(&e.Event).Error; err != nil {
				return err
			}
			e.EventID = e.Event.ID
			if err := tx.Save(&e).Error; err != nil {
				return err
			}
		}

		for _, e := range res.HTTP {
			if err := tx.Save(&e.Event).Error; err != nil {
				return err
			}
			e.EventID = e.Event.ID
			if err := tx.Save(&e).Error; err != nil {
				return err
			}
		}

		for _, e := range res.TLS {
			if err := tx.Save(&e.Event).Error; err != nil {
				return err
			}
			e.EventID = e.Event.ID
			if err := tx.Save(&e).Error; err != nil {
				return err
			}
		}

		for _, e := range res.ICMP {
			if err := tx.Save(&e.Event).Error; err != nil {
				return err
			}
			e.EventID = e.Event.ID
			if err := tx.Save(&e).Error; err != nil {
				return err
			}
		}

		return nil
	})
}

// GetFlows retrieves enriched flows with optional limit.
func (s *PostgresStore) GetFlows(limit int) ([]models.EnrichedFlow, error) {
	var flows []models.EnrichedFlow
	err := s.db.Preload("Flow").Preload("FlowHealth").Limit(limit).Order("created_at desc").Find(&flows).Error
	return flows, err
}

// Close closes the database connection.
func (s *PostgresStore) Close() error {
	sqlDB, err := s.db.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}
