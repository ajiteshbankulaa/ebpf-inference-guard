
package main

import (
    "encoding/binary"
    "math"
    "net/netip"
    "testing"
)

// Helper for comparing floating-point numbers.
func almostEqual(a, b float64) bool {
    return math.Abs(a-b) < 1e-6
}

// Test PPS, SYN ratio, and packet size.
func TestFlowFeatures(t *testing.T) {
    var w flowWindow

    // Sample 1: TCP SYN, 60 bytes.
    w.observe(shieldFlowEvent{
        TsNs:     1_000_000_000,
        PktLen:   60,
        Protocol: 6,
        TcpFlags: 0x02,
    })

    // Sample 2: TCP ACK, 100 bytes.
    w.observe(shieldFlowEvent{
        TsNs:     1_200_000_000,
        PktLen:   100,
        Protocol: 6,
        TcpFlags: 0x10,
    })

    f := w.features(1.0)

    // Two samples, sampling factor 64, one second.
    if !almostEqual(f.PPS, 128) {
        t.Errorf("PPS: got %f, want 128", f.PPS)
    }

    // One SYN out of two TCP packets.
    if !almostEqual(f.SynRatio, 0.5) {
        t.Errorf(
            "SYN ratio: got %f, want 0.5",
            f.SynRatio,
        )
    }

    // Mean of 60 and 100 is 80.
    if !almostEqual(f.MeanPacketBytes, 80) {
        t.Errorf(
            "mean bytes: got %f, want 80",
            f.MeanPacketBytes,
        )
    }
}

// Test inter-arrival-time coefficient of variation.
func TestIATCV(t *testing.T) {
    var w flowWindow

    // Timestamps produce gaps:
    // 0.1s, 0.2s, 0.3s.
    timestamps := []uint64{
        1_000_000_000,
        1_100_000_000,
        1_300_000_000,
        1_600_000_000,
    }

    for _, timestamp := range timestamps {
        w.observe(shieldFlowEvent{
            TsNs:     timestamp,
            PktLen:   64,
            Protocol: 6,
        })
    }

    // Population CV for [0.1, 0.2, 0.3].
    expected := math.Sqrt(1.0 / 6.0)
    actual := w.features(1.0).IATCV

    if !almostEqual(actual, expected) {
        t.Errorf(
            "IAT CV: got %f, want %f",
            actual, expected,
        )
    }
}

// Verify how we reconstruct network-order IPv4 bytes.
func TestEventSource(t *testing.T) {
    rawIP := [4]byte{10, 200, 1, 1}

    event := shieldFlowEvent{
        SrcIp: binary.NativeEndian.Uint32(rawIP[:]),
    }

    got := eventSource(event)
    want := netip.MustParseAddr("10.200.1.1")

    if got != want {
        t.Errorf("source IP: got %s, want %s", got, want)
    }
}

// Empty windows must not produce division-by-zero.
func TestEmptyWindow(t *testing.T) {
    var w flowWindow

    f := w.features(1.0)

    if f.PPS != 0 ||
        f.SynRatio != 0 ||
        f.MeanPacketBytes != 0 ||
        f.IATCV != 0 {
        t.Errorf("empty window should have zero features")
    }
}
