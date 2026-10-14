package main

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestMetricsExposeShieldSeries(t *testing.T) {
	m := newShieldMetrics()
	m.observeKernelCounters(counterValue{Pass: 7, Drop: 2, Malformed: 1, RingbufLost: 3})
	m.ringbufEvents.Add(5)
	m.userEventLoss.Add(1)
	m.activeBlocks.Set(4)
	m.anomalyDecisions.Inc()
	m.detectionToBlock.Observe(0.001)

	response := httptest.NewRecorder()
	m.handler().ServeHTTP(response, httptest.NewRequest("GET", "/shield/metrics", nil))
	for _, metric := range []string{
		"shield_packets_passed_total 7",
		"shield_packets_dropped_total 2",
		"shield_ringbuf_events_total 5",
		"shield_ringbuf_lost_total 3",
		"shield_active_block_entries 4",
		"shield_anomaly_decisions_total 1",
		"shield_detection_to_block_seconds_count 1",
	} {
		if !strings.Contains(response.Body.String(), metric) {
			t.Errorf("metrics output missing %q", metric)
		}
	}
}

func TestBlockGaugeRefreshInterval(t *testing.T) {
	m := newShieldMetrics()
	now := time.Now()
	if !m.shouldRefreshBlockGauge(now) {
		t.Fatal("first scan should run")
	}
	if m.shouldRefreshBlockGauge(now.Add(29 * time.Second)) {
		t.Fatal("scan should be throttled within 30 seconds")
	}
	if !m.shouldRefreshBlockGauge(now.Add(30 * time.Second)) {
		t.Fatal("scan should run at 30 seconds")
	}
}
