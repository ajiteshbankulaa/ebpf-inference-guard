package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func testServer() *server {
	return &server{
		maxOutputTokens: 32768,
		maxCostScore:    20000,
		alpha:           0.25,
		beta:            8,
		semaphore:       make(chan struct{}, 8),
		metrics:         newGatewayMetrics(),
	}
}

func TestAdmissionAllowsAndReportsSignals(t *testing.T) {
	s := testServer()
	req := httptest.NewRequest(http.MethodPost, "/v1/admit", strings.NewReader(`{"model":"example-model","prompt":"12345678","max_tokens":100}`))
	req.RemoteAddr = "192.0.2.8:43210"
	req.Header.Set("X-Tenant-ID", "tenant-a")
	res := httptest.NewRecorder()
	s.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", res.Code, res.Body.String())
	}
	var got admissionResponse
	if err := json.Unmarshal(res.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Decision != "allow" || got.EstimatedInputTokens != 2 || got.RequestedMaxTokens != 100 || got.RequestBytes == 0 {
		t.Fatalf("unexpected admission response: %+v", got)
	}
	metrics := httptest.NewRecorder()
	s.ServeHTTP(metrics, httptest.NewRequest(http.MethodGet, "/shield/metrics", nil))
	for _, want := range []string{
		"shield_gateway_requests_total{decision=\"allow\"} 1",
		"shield_gateway_requests_by_tenant_total{tenant=\"tenant-a\"} 1",
		"shield_gateway_requests_by_source_ip_total{source_ip=\"192.0.2.8\"} 1",
	} {
		if !strings.Contains(metrics.Body.String(), want) {
			t.Errorf("metrics missing %q", want)
		}
	}
}

func TestAdmissionRejectsOverBudgetAndInvalidRequests(t *testing.T) {
	s := testServer()
	s.maxCostScore = 3
	req := httptest.NewRequest(http.MethodPost, "/v1/admit", strings.NewReader(`{"model":"example-model","prompt":"12345678","max_tokens":1}`))
	res := httptest.NewRecorder()
	s.ServeHTTP(res, req)
	if res.Code != http.StatusTooManyRequests {
		t.Fatalf("budget status=%d, want 429", res.Code)
	}

	bad := httptest.NewRequest(http.MethodPost, "/v1/admit", strings.NewReader(`{"model":"","prompt":"x","max_tokens":0}`))
	badRes := httptest.NewRecorder()
	s.ServeHTTP(badRes, bad)
	if badRes.Code != http.StatusUnprocessableEntity {
		t.Fatalf("invalid status=%d, want 422", badRes.Code)
	}
}

func TestAdmissionRejectsExtraJSONAndWrongMethod(t *testing.T) {
	s := testServer()
	extra := httptest.NewRequest(http.MethodPost, "/v1/admit", strings.NewReader(`{"model":"m","prompt":"p","max_tokens":1} {}`))
	extraRes := httptest.NewRecorder()
	s.ServeHTTP(extraRes, extra)
	if extraRes.Code != http.StatusBadRequest {
		t.Fatalf("extra JSON status=%d, want 400", extraRes.Code)
	}

	wrong := httptest.NewRequest(http.MethodGet, "/v1/admit", nil)
	wrongRes := httptest.NewRecorder()
	s.ServeHTTP(wrongRes, wrong)
	if wrongRes.Code != http.StatusMethodNotAllowed {
		t.Fatalf("method status=%d, want 405", wrongRes.Code)
	}
}

func TestLabelLimiterBoundsCardinality(t *testing.T) {
	limiter := newLabelLimiter(1)
	if got := limiter.label("first"); got != "first" {
		t.Fatalf("first label=%q", got)
	}
	if got := limiter.label("second"); got != "other" {
		t.Fatalf("overflow label=%q, want other", got)
	}
}
