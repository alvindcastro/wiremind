package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"wiremind/config"
	"wiremind/internal/enrichment"
	"wiremind/internal/models"
	"wiremind/internal/queue"
	"wiremind/internal/store"
)

func setupTestStore(t *testing.T) *store.PostgresStore {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("Failed to connect to test db: %v", err)
	}
	return store.NewTestStore(db)
}

func TestServerConfigAndIOC(t *testing.T) {
	st := setupTestStore(t)
	pipeline, _ := enrichment.NewPipeline(&config.Config{})
	server := NewServer(&config.Config{}, pipeline, st, nil)

	t.Run("POST /api/v1/config/ioc", func(t *testing.T) {
		body := `{"indicator": "evil.com", "type": "domain"}`
		req := httptest.NewRequest("POST", "/api/v1/config/ioc", bytes.NewBufferString(body))
		w := httptest.NewRecorder()

		server.handleAddIOC(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}

		var entry models.IOCEntry
		json.NewDecoder(w.Body).Decode(&entry)
		if entry.Indicator != "evil.com" {
			t.Errorf("Expected indicator evil.com, got %s", entry.Indicator)
		}

		// Verify matcher updated
		if len(pipeline.IOC.MatchDomain("evil.com")) == 0 {
			t.Errorf("Matcher was not updated with new IOC")
		}
	})

	t.Run("GET /api/v1/config/ioc", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/config/ioc", nil)
		w := httptest.NewRecorder()
		server.handleListIOC(w, req)

		var entries []models.IOCEntry
		json.NewDecoder(w.Body).Decode(&entries)
		if len(entries) != 1 {
			t.Errorf("Expected 1 entry, got %d", len(entries))
		}
	})

	t.Run("PATCH /api/v1/config/pipeline", func(t *testing.T) {
		body := `{"key": "test_threshold", "value": "0.5"}`
		req := httptest.NewRequest("PATCH", "/api/v1/config/pipeline", bytes.NewBufferString(body))
		w := httptest.NewRecorder()
		server.handleUpdateConfig(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}
	})

	t.Run("POST /api/v1/capture/start", func(t *testing.T) {
		body := `{"interface": "eth0", "filter": "tcp"}`
		req := httptest.NewRequest("POST", "/api/v1/capture/start", bytes.NewBufferString(body))
		w := httptest.NewRecorder()
		server.handleStartCapture(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}
	})
}

func TestServerFlows(t *testing.T) {
	cfg := &config.Config{ToolServerPort: 8765}
	server := NewServer(cfg, nil, nil, nil)

	mockFlows := []models.EnrichedFlow{
		{FlowID: "flow-1", EntropyScore: 3.14},
		{FlowID: "flow-2", EntropyScore: 1.23},
	}
	server.UpdateResults(enrichment.EnrichedResult{
		Flows: mockFlows,
	})

	t.Run("GET /api/v1/flows", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/flows", nil)
		w := httptest.NewRecorder()

		server.handleFlows(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}

		var flows []models.EnrichedFlow
		if err := json.NewDecoder(w.Body).Decode(&flows); err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}

		if len(flows) != 2 {
			t.Errorf("Expected 2 flows, got %d", len(flows))
		}
	})

	t.Run("GET /api/v1/stats", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/stats", nil)
		w := httptest.NewRecorder()

		server.handleStats(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}

		var stats map[string]int
		if err := json.NewDecoder(w.Body).Decode(&stats); err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}

		if stats["flows"] != 2 {
			t.Errorf("Expected flow count 2, got %d", stats["flows"])
		}
	})
}

type MockQueue struct {
	Published []queue.Job
}

func (m *MockQueue) PublishJob(ctx context.Context, job queue.Job) error {
	m.Published = append(m.Published, job)
	return nil
}

func TestServerJobs(t *testing.T) {
	cfg := &config.Config{ToolServerPort: 8765}
	mq := &MockQueue{}
	server := NewServer(cfg, nil, nil, mq)

	t.Run("POST /api/v1/jobs - success", func(t *testing.T) {
		body := `{"input_path": "test.pcap", "output_path": "./out"}`
		req := httptest.NewRequest("POST", "/api/v1/jobs", bytes.NewBufferString(body))
		w := httptest.NewRecorder()

		server.handleSubmitJob(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}

		var res map[string]string
		json.NewDecoder(w.Body).Decode(&res)
		if res["status"] != "pending" {
			t.Errorf("Expected status pending, got %s", res["status"])
		}

		if len(mq.Published) != 1 {
			t.Errorf("Expected 1 published job, got %d", len(mq.Published))
		}
	})

	t.Run("POST /api/v1/jobs - missing input", func(t *testing.T) {
		body := `{"output_path": "./out"}`
		req := httptest.NewRequest("POST", "/api/v1/jobs", bytes.NewBufferString(body))
		w := httptest.NewRecorder()

		server.handleSubmitJob(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected status 400, got %d", w.Code)
		}
	})
}

func TestServerJobStream(t *testing.T) {
	st := setupTestStore(t)
	server := NewServer(&config.Config{}, nil, st, nil)

	jobID := "test-job-stream"
	job := &models.Job{
		ID:     jobID,
		Status: models.JobPending,
	}
	st.SaveJob(job)

	t.Run("GET /api/v1/jobs/{id}/stream", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/jobs/"+jobID+"/stream", nil)
		// Use PathValue for standard library mux
		req.SetPathValue("id", jobID)

		ctx, cancel := context.WithCancel(context.Background())
		req = req.WithContext(ctx)

		w := httptest.NewRecorder()

		// Run handleJobStream in a goroutine because it's a blocking loop
		done := make(chan bool)
		go func() {
			server.handleJobStream(w, req)
			done <- true
		}()

		// Wait for at least one ticker cycle (2s)
		// To speed up tests we could mock the ticker, but for a simple test we just wait a bit
		// Actually, let's update the job status in the background to trigger completion
		go func() {
			time.Sleep(2500 * time.Millisecond)
			job.Status = models.JobCompleted
			st.SaveJob(job)
			// Wait another cycle for the stream to pick up completion and exit
		}()

		select {
		case <-done:
			// Success
		case <-time.After(6 * time.Second):
			cancel()
			t.Fatal("Test timed out waiting for job stream to complete")
		}

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}

		if w.Header().Get("Content-Type") != "text/event-stream" {
			t.Errorf("Expected content-type text/event-stream, got %s", w.Header().Get("Content-Type"))
		}

		// Verify we got some data
		if w.Body.Len() == 0 {
			t.Error("Expected stream data, got empty body")
		}
	})
}
