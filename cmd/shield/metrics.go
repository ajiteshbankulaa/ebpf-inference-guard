package main

import (
	"net/http"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type shieldMetrics struct {
	registry         *prometheus.Registry
	packetsPassed    prometheus.Counter
	packetsDropped   prometheus.Counter
	malformedPackets prometheus.Counter
	ringbufLost      prometheus.Counter
	ringbufEvents    prometheus.Counter
	userEventLoss    prometheus.Counter
	activeBlocks     prometheus.Gauge
	anomalyDecisions prometheus.Counter
	detectionToBlock prometheus.Histogram
	mu               sync.Mutex
	lastKernel       counterValue
	lastBlockScan    time.Time
}

func (m *shieldMetrics) shouldRefreshBlockGauge(now time.Time) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.lastBlockScan.IsZero() && now.Sub(m.lastBlockScan) < 30*time.Second {
		return false
	}
	m.lastBlockScan = now
	return true
}

func (m *shieldMetrics) observeKernelCounters(current counterValue) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if current.Pass >= m.lastKernel.Pass {
		m.packetsPassed.Add(float64(current.Pass - m.lastKernel.Pass))
	}
	if current.Drop >= m.lastKernel.Drop {
		m.packetsDropped.Add(float64(current.Drop - m.lastKernel.Drop))
	}
	if current.Malformed >= m.lastKernel.Malformed {
		m.malformedPackets.Add(float64(current.Malformed - m.lastKernel.Malformed))
	}
	if current.RingbufLost >= m.lastKernel.RingbufLost {
		m.ringbufLost.Add(float64(current.RingbufLost - m.lastKernel.RingbufLost))
	}
	m.lastKernel = current
}

var runtimeMetrics = newShieldMetrics()

func newShieldMetrics() *shieldMetrics {
	m := &shieldMetrics{registry: prometheus.NewRegistry()}
	m.packetsPassed = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "shield_packets_passed_total", Help: "Packets passed by XDP.",
	})
	m.packetsDropped = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "shield_packets_dropped_total", Help: "Packets dropped by XDP.",
	})
	m.malformedPackets = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "shield_packets_malformed_total", Help: "Malformed packets passed by XDP.",
	})
	m.ringbufLost = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "shield_ringbuf_lost_total", Help: "Events lost when the kernel ring buffer was full.",
	})
	m.ringbufEvents = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "shield_ringbuf_events_total", Help: "Events successfully read from the kernel ring buffer.",
	})
	m.userEventLoss = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "shield_userspace_event_loss_total", Help: "Events dropped because the userspace queue was full.",
	})
	m.activeBlocks = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "shield_active_block_entries", Help: "Currently effective source-IP block entries.",
	})
	m.anomalyDecisions = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "shield_anomaly_decisions_total", Help: "Anomaly decisions made by the configured detector.",
	})
	m.detectionToBlock = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name: "shield_detection_to_block_seconds", Help: "Time from a positive detection decision to the block map update.",
		Buckets: prometheus.DefBuckets,
	})
	m.registry.MustRegister(
		m.packetsPassed, m.packetsDropped, m.malformedPackets,
		m.ringbufLost, m.ringbufEvents, m.userEventLoss,
		m.activeBlocks, m.anomalyDecisions, m.detectionToBlock,
	)
	return m
}

func (m *shieldMetrics) handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}
