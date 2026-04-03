package models

import (
	"time"

	"gorm.io/gorm"
)

type JobStatus string

const (
	JobPending    JobStatus = "pending"
	JobProcessing JobStatus = "processing"
	JobCompleted  JobStatus = "completed"
	JobFailed     JobStatus = "failed"
)

type Job struct {
	ID          string         `gorm:"primaryKey" json:"id"`
	InputPath   string         `json:"input_path"`
	OutputPath  string         `json:"output_path"`
	Status      JobStatus      `gorm:"index" json:"status"`
	Error       string         `json:"error,omitempty"`
	PacketCount int            `json:"packet_count"`
	FlowCount   int            `json:"flow_count"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	DeletedAt   gorm.DeletedAt `gorm:"index" json:"-"`
}
