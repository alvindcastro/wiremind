package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"wiremind/config"
	"wiremind/internal/enrichment"
	"wiremind/internal/models"
)

func TestServerFlows(t *testing.T) {
	cfg := &config.Config{ToolServerPort: 8765}
	server := NewServer(cfg, nil, nil)

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
