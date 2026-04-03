package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"wiremind/config"
	"wiremind/internal/enrichment"
	"wiremind/internal/models"
	"wiremind/internal/queue"
)

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
