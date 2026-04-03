package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"wiremind/config"
	"wiremind/internal/enrichment"
	"wiremind/internal/models"
	"wiremind/internal/queue"
	"wiremind/internal/store"
)

var (
	requestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "wiremind_api_requests_total",
		Help: "Total number of HTTP requests to the Wiremind API",
	}, []string{"method", "endpoint", "status"})

	requestDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "wiremind_api_request_duration_seconds",
		Help:    "Duration of HTTP requests to the Wiremind API in seconds",
		Buckets: prometheus.DefBuckets,
	}, []string{"method", "endpoint"})
)

// Server provides a JSON API for retrieving enriched forensics results.
type Server struct {
	cfg      *config.Config
	pipeline *enrichment.Pipeline
	store    *store.PostgresStore
	queue    interface {
		PublishJob(context.Context, queue.Job) error
	}
	results enrichment.EnrichedResult
	mu      sync.RWMutex
}

func NewServer(cfg *config.Config, p *enrichment.Pipeline, s *store.PostgresStore, q interface {
	PublishJob(context.Context, queue.Job) error
}) *Server {
	return &Server{
		cfg:      cfg,
		pipeline: p,
		store:    s,
		queue:    q,
	}
}

// UpdateResults replaces the current in-memory dataset with a new enriched result.
func (s *Server) UpdateResults(res enrichment.EnrichedResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.results = res
	slog.Info("api server: dataset updated", "flows", len(res.Flows))
}

func (s *Server) Start() error {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/v1/flows", s.instrument("flows", s.handleFlows))
	mux.HandleFunc("GET /api/v1/jobs", s.instrument("list_jobs", s.handleListJobs))
	mux.HandleFunc("POST /api/v1/jobs", s.instrument("submit_job", s.handleSubmitJob))
	mux.HandleFunc("GET /api/v1/jobs/{id}", s.instrument("get_job", s.handleGetJob))
	mux.HandleFunc("GET /api/v1/dns", s.instrument("dns", s.handleDNS))
	mux.HandleFunc("GET /api/v1/tls", s.instrument("tls", s.handleTLS))
	mux.HandleFunc("GET /api/v1/http", s.instrument("http", s.handleHTTP))
	mux.HandleFunc("GET /api/v1/icmp", s.instrument("icmp", s.handleICMP))
	mux.HandleFunc("GET /api/v1/stats", s.instrument("stats", s.handleStats))
	mux.HandleFunc("GET /health", s.handleHealth)
	mux.Handle("GET /metrics", promhttp.Handler())

	addr := ":" + strconv.Itoa(s.cfg.ToolServerPort)
	slog.Info("api server starting", "addr", addr)

	return http.ListenAndServe(addr, mux)
}

func (s *Server) instrument(endpoint string, handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &responseWriter{ResponseWriter: w, status: http.StatusOK}

		defer func() {
			duration := time.Since(start).Seconds()
			requestDuration.WithLabelValues(r.Method, endpoint).Observe(duration)
			requestsTotal.WithLabelValues(r.Method, endpoint, strconv.Itoa(rw.status)).Inc()
		}()

		handler(rw, r)
	}
}

type responseWriter struct {
	http.ResponseWriter
	status int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}

func (s *Server) handleFlows(w http.ResponseWriter, r *http.Request) {
	if s.store != nil {
		limit := 100
		if l, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && l > 0 {
			limit = l
		}
		flows, err := s.store.GetFlows(limit)
		if err != nil {
			http.Error(w, "database error", http.StatusInternalServerError)
			return
		}
		s.writeJSON(w, flows)
		return
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	s.writeJSON(w, s.results.Flows)
}

func (s *Server) handleDNS(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	s.writeJSON(w, s.results.DNS)
}

func (s *Server) handleTLS(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	s.writeJSON(w, s.results.TLS)
}

func (s *Server) handleHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	s.writeJSON(w, s.results.HTTP)
}

func (s *Server) handleICMP(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	s.writeJSON(w, s.results.ICMP)
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stats := map[string]int{
		"flows": len(s.results.Flows),
		"dns":   len(s.results.DNS),
		"tls":   len(s.results.TLS),
		"http":  len(s.results.HTTP),
		"icmp":  len(s.results.ICMP),
	}
	s.writeJSON(w, stats)
}

func (s *Server) handleListJobs(w http.ResponseWriter, r *http.Request) {
	if s.store == nil {
		http.Error(w, "persistence disabled", http.StatusNotImplemented)
		return
	}

	limit := 50
	if l, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && l > 0 {
		limit = l
	}

	jobs, err := s.store.GetJobs(limit)
	if err != nil {
		http.Error(w, "database error", http.StatusInternalServerError)
		return
	}
	s.writeJSON(w, jobs)
}

func (s *Server) handleGetJob(w http.ResponseWriter, r *http.Request) {
	if s.store == nil {
		http.Error(w, "persistence disabled", http.StatusNotImplemented)
		return
	}

	id := r.PathValue("id")
	if id == "" {
		http.Error(w, "missing job id", http.StatusBadRequest)
		return
	}

	job, err := s.store.GetJob(id)
	if err != nil {
		http.Error(w, "job not found", http.StatusNotFound)
		return
	}
	s.writeJSON(w, job)
}

func (s *Server) handleSubmitJob(w http.ResponseWriter, r *http.Request) {
	if s.queue == nil {
		http.Error(w, "async queue disabled", http.StatusNotImplemented)
		return
	}

	var req struct {
		InputPath  string `json:"input_path"`
		OutputPath string `json:"output_path"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.InputPath == "" {
		http.Error(w, "input_path is required", http.StatusBadRequest)
		return
	}

	jobID := uuid.New().String()
	job := queue.Job{
		ID:         jobID,
		InputPath:  req.InputPath,
		OutputPath: req.OutputPath,
		CreatedAt:  time.Now(),
	}

	// Persist job as pending if DB enabled
	if s.store != nil {
		dbJob := &models.Job{
			ID:         job.ID,
			InputPath:  job.InputPath,
			OutputPath: job.OutputPath,
			Status:     models.JobPending,
			CreatedAt:  job.CreatedAt,
		}
		if err := s.store.SaveJob(dbJob); err != nil {
			slog.Error("failed to persist job status", "err", err, "job_id", jobID)
		}
	}

	if err := s.queue.PublishJob(r.Context(), job); err != nil {
		slog.Error("failed to publish job", "err", err, "job_id", jobID)
		http.Error(w, "failed to enqueue job", http.StatusInternalServerError)
		return
	}

	s.writeJSON(w, map[string]string{
		"job_id": jobID,
		"status": "pending",
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	health := map[string]string{
		"status": "up",
	}

	if s.cfg.Postgres.Enabled {
		if s.store != nil {
			if err := s.store.Ping(); err != nil {
				health["postgres"] = "down"
				health["status"] = "degraded"
			} else {
				health["postgres"] = "up"
			}
		} else {
			health["postgres"] = "not_initialized"
			health["status"] = "degraded"
		}
	}

	s.writeJSON(w, health)
}

func (s *Server) writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Error("api: encode error", "err", err)
	}
}
