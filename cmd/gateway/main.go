package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const maxRequestBytes = 1 << 20

type admissionRequest struct {
	Model     string `json:"model"`
	Prompt    string `json:"prompt"`
	MaxTokens int    `json:"max_tokens"`
}

type admissionResponse struct {
	ID                   string  `json:"id"`
	Model                string  `json:"model"`
	Decision             string  `json:"decision"`
	RequestBytes         int     `json:"request_bytes"`
	EstimatedInputTokens int     `json:"estimated_input_tokens"`
	RequestedMaxTokens   int     `json:"requested_max_tokens"`
	ConcurrentRequests   int     `json:"concurrent_requests"`
	CostScore            float64 `json:"cost_score"`
}

type labelLimiter struct {
	mu   sync.Mutex
	seen map[string]struct{}
	max  int
}

func newLabelLimiter(max int) *labelLimiter {
	return &labelLimiter{seen: make(map[string]struct{}), max: max}
}

func (l *labelLimiter) label(raw string) string {
	if raw == "" {
		return "unknown"
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.seen[raw]; ok {
		return raw
	}
	if len(l.seen) >= l.max {
		return "other"
	}
	l.seen[raw] = struct{}{}
	return raw
}

type gatewayMetrics struct {
	registry     *prometheus.Registry
	requests     *prometheus.CounterVec
	requestBytes prometheus.Histogram
	inputTokens  prometheus.Histogram
	maxOutput    prometheus.Histogram
	inFlight     prometheus.Gauge
	byTenant     *prometheus.CounterVec
	bySource     *prometheus.CounterVec
	tenants      *labelLimiter
	sources      *labelLimiter
}

func newGatewayMetrics() *gatewayMetrics {
	g := &gatewayMetrics{registry: prometheus.NewRegistry()}
	g.requests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "shield_gateway_requests_total", Help: "Admission decisions by outcome.",
	}, []string{"decision"})
	g.requestBytes = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name: "shield_gateway_request_bytes", Help: "Request body size in bytes.",
		Buckets: prometheus.ExponentialBuckets(128, 2, 14),
	})
	g.inputTokens = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name: "shield_gateway_estimated_input_tokens", Help: "Estimated input token count (UTF-8 bytes divided by four).",
		Buckets: prometheus.ExponentialBuckets(1, 2, 16),
	})
	g.maxOutput = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name: "shield_gateway_requested_max_output_tokens", Help: "Requested max_tokens value.",
		Buckets: prometheus.ExponentialBuckets(1, 2, 16),
	})
	g.inFlight = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "shield_gateway_concurrent_requests", Help: "Requests currently being admitted.",
	})
	g.byTenant = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "shield_gateway_requests_by_tenant_total", Help: "Admission requests grouped by tenant.",
	}, []string{"tenant"})
	g.bySource = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "shield_gateway_requests_by_source_ip_total", Help: "Admission requests grouped by observed remote IP.",
	}, []string{"source_ip"})
	g.tenants = newLabelLimiter(128)
	g.sources = newLabelLimiter(256)
	g.registry.MustRegister(g.requests, g.requestBytes, g.inputTokens, g.maxOutput, g.inFlight, g.byTenant, g.bySource)
	return g
}

type server struct {
	maxOutputTokens int
	maxCostScore    float64
	alpha           float64
	beta            float64
	semaphore       chan struct{}
	metrics         *gatewayMetrics
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/healthz":
		w.WriteHeader(http.StatusNoContent)
		return
	case "/shield/metrics":
		promhttp.HandlerFor(s.metrics.registry, promhttp.HandlerOpts{}).ServeHTTP(w, r)
		return
	case "/v1/admit":
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
	default:
		http.NotFound(w, r)
		return
	}

	select {
	case s.semaphore <- struct{}{}:
		defer func() {
			<-s.semaphore
			s.metrics.inFlight.Set(float64(len(s.semaphore)))
		}()
	default:
		s.metrics.requests.WithLabelValues("busy").Inc()
		http.Error(w, "gateway at concurrency limit", http.StatusServiceUnavailable)
		return
	}
	active := len(s.semaphore)
	s.metrics.inFlight.Set(float64(active))

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		status := http.StatusBadRequest
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			status = http.StatusRequestEntityTooLarge
		}
		s.metrics.requests.WithLabelValues("invalid").Inc()
		http.Error(w, "invalid request body", status)
		return
	}
	var input admissionRequest
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil || decoder.Decode(new(any)) != io.EOF {
		s.metrics.requests.WithLabelValues("invalid").Inc()
		http.Error(w, "expected one valid JSON request", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(input.Model) == "" || len(input.Model) > 128 || input.Prompt == "" || input.MaxTokens < 1 || input.MaxTokens > s.maxOutputTokens {
		s.metrics.requests.WithLabelValues("invalid").Inc()
		http.Error(w, fmt.Sprintf("model, prompt, or max_tokens is invalid (max_tokens must be 1..%d)", s.maxOutputTokens), http.StatusUnprocessableEntity)
		return
	}

	inputTokens := (len([]byte(input.Prompt)) + 3) / 4
	score := float64(inputTokens) + s.alpha*float64(input.MaxTokens) + s.beta*float64(active)
	decision := "allow"
	status := http.StatusOK
	if score > s.maxCostScore {
		decision = "reject"
		status = http.StatusTooManyRequests
	}
	s.metrics.requestBytes.Observe(float64(len(body)))
	s.metrics.inputTokens.Observe(float64(inputTokens))
	s.metrics.maxOutput.Observe(float64(input.MaxTokens))
	s.metrics.requests.WithLabelValues(decision).Inc()
	tenant := s.metrics.tenants.label(r.Header.Get("X-Tenant-ID"))
	s.metrics.byTenant.WithLabelValues(tenant).Inc()
	s.metrics.bySource.WithLabelValues(s.metrics.sources.label(remoteIP(r.RemoteAddr))).Inc()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(admissionResponse{
		ID: fmt.Sprintf("admit-%d", time.Now().UnixNano()), Model: input.Model,
		Decision: decision, RequestBytes: len(body), EstimatedInputTokens: inputTokens,
		RequestedMaxTokens: input.MaxTokens, ConcurrentRequests: active, CostScore: score,
	})
}

func remoteIP(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	parsed, err := netip.ParseAddr(host)
	if err != nil {
		return "unknown"
	}
	return parsed.Unmap().String()
}

func main() {
	listen := flag.String("listen", ":8080", "HTTP listen address")
	metricsAddr := flag.String("metrics-listen", ":9101", "Prometheus metrics listen address")
	maxOutput := flag.Int("max-output-tokens", 32768, "Maximum accepted max_tokens")
	maxConcurrent := flag.Int("max-concurrent", 128, "Maximum concurrent admission requests")
	maxScore := flag.Float64("max-cost-score", 20000, "Maximum admitted estimated cost score")
	alpha := flag.Float64("output-weight", 0.25, "Weight for requested output tokens in the score")
	beta := flag.Float64("concurrency-weight", 8, "Weight for concurrent requests in the score")
	flag.Parse()
	if *maxOutput < 1 || *maxConcurrent < 1 || *maxScore <= 0 || *alpha < 0 || *beta < 0 {
		log.Fatal("token, concurrency, and score limits must be positive; score weights cannot be negative")
	}

	metrics := newGatewayMetrics()
	app := &server{
		maxOutputTokens: *maxOutput, maxCostScore: *maxScore,
		alpha: *alpha, beta: *beta, semaphore: make(chan struct{}, *maxConcurrent), metrics: metrics,
	}
	appServer := &http.Server{Addr: *listen, Handler: app, ReadHeaderTimeout: 5 * time.Second}
	metricsServer := &http.Server{Addr: *metricsAddr, Handler: app, ReadHeaderTimeout: 5 * time.Second}
	errs := make(chan error, 2)
	go func() { errs <- appServer.ListenAndServe() }()
	go func() { errs <- metricsServer.ListenAndServe() }()
	select {
	case err := <-errs:
		if err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	case <-waitSignal():
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = appServer.Shutdown(ctx)
	_ = metricsServer.Shutdown(ctx)
}

func waitSignal() <-chan struct{} {
	ch := make(chan struct{})
	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
		<-c
		signal.Stop(c)
		close(ch)
	}()
	return ch
}
