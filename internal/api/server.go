package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"wiremind/config"
	"wiremind/internal/enrichment"
	"wiremind/internal/store"
)

// Server provides a JSON API for retrieving enriched forensics results.
type Server struct {
	cfg      *config.Config
	pipeline *enrichment.Pipeline
	store    *store.PostgresStore
	results  enrichment.EnrichedResult
	mu       sync.RWMutex

	// Metrics
	requestsTotal   *prometheus.CounterVec
	requestDuration *prometheus.HistogramVec
}

func NewServer(cfg *config.Config, p *enrichment.Pipeline, s *store.PostgresStore) *Server {
	srv := &Server{
		cfg:      cfg,
		pipeline: p,
		store:    s,
	}

	srv.requestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "wiremind_api_requests_total",
		Help: "Total number of HTTP requests to the Wiremind API",
	}, []string{"method", "endpoint", "status"})

	srv.requestDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "wiremind_api_request_duration_seconds",
		Help:    "Duration of HTTP requests to the Wiremind API in seconds",
		Buckets: prometheus.DefBuckets,
	}, []string{"method", "endpoint"})

	return srv
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
			s.requestDuration.WithLabelValues(r.Method, endpoint).Observe(duration)
			s.requestsTotal.WithLabelValues(r.Method, endpoint, strconv.Itoa(rw.status)).Inc()
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
