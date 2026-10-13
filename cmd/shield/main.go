package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"
)

// Must match struct block_entry in shield.bpf.c.
type blockEntry struct {
	ExpiresNS uint64
	Reason    uint32
	Reserved  uint32
}

// Must match struct counters in shield.bpf.c.
type counterValue struct {
	Pass        uint64
	Drop        uint64
	Malformed   uint64
	RingbufLost uint64
}

// Manual blocks use reason 1.
func addBlock(
	m *ebpf.Map,
	address string,
	ttl time.Duration,
) error {
	return addBlockWithReason(m, address, ttl, 1)
}

// Used by both manual commands and automatic detection.
func addBlockWithReason(
	m *ebpf.Map,
	address string,
	ttl time.Duration,
	reason uint32,
) error {
	// Parse the source address.
	ip, err := netip.ParseAddr(address)

	if err != nil || !ip.Is4() {
		return fmt.Errorf(
			"invalid IPv4 address: %q", address,
		)
	}

	if ttl < 0 {
		return fmt.Errorf("TTL cannot be negative")
	}

	// Zero expiration means permanent.
	entry := blockEntry{
		Reason: reason,
	}

	if ttl > 0 {
		// Match the clock used by bpf_ktime_get_ns().
		var now unix.Timespec

		if err := unix.ClockGettime(
			unix.CLOCK_MONOTONIC, &now,
		); err != nil {
			return fmt.Errorf(
				"read monotonic clock: %w", err,
			)
		}

		currentNS :=
			uint64(now.Sec)*1_000_000_000 +
				uint64(now.Nsec)

		entry.ExpiresNS =
			currentNS + uint64(ttl.Nanoseconds())
	}

	// Store four raw IPv4 key bytes in the BPF map.
	return m.Update(
		ip.As4(),
		entry,
		ebpf.UpdateAny,
	)
}

// Delete an IP address from the BPF blocklist.
func removeBlock(
	m *ebpf.Map,
	address string,
) error {
	ip, err := netip.ParseAddr(address)

	if err != nil || !ip.Is4() {
		return fmt.Errorf(
			"invalid IPv4 address: %q", address,
		)
	}

	return m.Delete(ip.As4())
}

// Read and sum the per-CPU kernel counters.
func printStats(m *ebpf.Map) {
	var perCPU []counterValue

	if err := m.Lookup(
		uint32(0), &perCPU,
	); err != nil {
		log.Printf(
			"[ERROR] stats lookup: %v", err,
		)
		return
	}

	var total counterValue

	for _, c := range perCPU {
		total.Pass += c.Pass
		total.Drop += c.Drop
		total.Malformed += c.Malformed
		total.RingbufLost += c.RingbufLost
	}

	log.Printf(
		"[STATS] pass=%d drop=%d malformed=%d ringbuf_lost=%d",
		total.Pass,
		total.Drop,
		total.Malformed,
		total.RingbufLost,
	)
}

// Keep our Day 1 interactive CLI.
func interactive(
	blocklist *ebpf.Map,
	stop context.CancelFunc,
) {
	scanner := bufio.NewScanner(os.Stdin)

	fmt.Println("Commands:")
	fmt.Println("  block 10.200.1.1 30s")
	fmt.Println("  block 10.200.1.1  (permanent)")
	fmt.Println("  unblock 10.200.1.1")
	fmt.Println("  quit")

	for scanner.Scan() {
		parts := strings.Fields(scanner.Text())

		if len(parts) == 0 {
			continue
		}

		switch parts[0] {
		case "block":
			if len(parts) < 2 || len(parts) > 3 {
				fmt.Println(
					"Usage: block <IPv4> [duration]",
				)
				continue
			}

			ttl := time.Duration(0)

			if len(parts) == 3 {
				var err error

				ttl, err = time.ParseDuration(parts[2])

				if err != nil {
					fmt.Printf(
						"Invalid duration: %v\n", err,
					)
					continue
				}
			}

			if err := addBlock(
				blocklist, parts[1], ttl,
			); err != nil {
				fmt.Printf(
					"Block failed: %v\n", err,
				)
				continue
			}

			fmt.Printf(
				"Blocked %s (TTL=%s)\n",
				parts[1], ttl,
			)

		case "unblock":
			if len(parts) != 2 {
				fmt.Println(
					"Usage: unblock <IPv4>",
				)
				continue
			}

			if err := removeBlock(
				blocklist, parts[1],
			); err != nil {
				fmt.Printf(
					"Unblock failed: %v\n", err,
				)
				continue
			}

			fmt.Printf(
				"Unblocked %s\n", parts[1],
			)

		case "quit", "exit":
			stop()
			return

		default:
			fmt.Println(
				"Unknown command. Use block, unblock, or quit.",
			)
		}
	}

	if err := scanner.Err(); err != nil {
		log.Printf(
			"terminal input error: %v", err,
		)
	}
}

func main() {
	// -------- Day 1 startup flags --------

	ifaceName := flag.String(
		"iface",
		"veth-v",
		"Network interface to protect",
	)

	mode := flag.String(
		"mode",
		"driver",
		"XDP mode: driver or generic",
	)

	staticBlock := flag.String(
		"static-block",
		"",
		"Optional initial blocked IPv4",
	)

	ttl := flag.Duration(
		"ttl",
		0,
		"Initial block duration (0 = permanent)",
	)

	// -------- New Day 2 flags --------

	detector := flag.String(
		"detector",
		"off",
		"Detector: off, rules, or tree",
	)

	ppsThreshold := flag.Float64(
		"pps-threshold",
		25000,
		"Estimated PPS threshold for rules",
	)

	minSamples := flag.Int(
		"min-samples",
		12,
		"Minimum samples per traffic window",
	)

	autoTTL := flag.Duration(
		"auto-ttl",
		30*time.Second,
		"Automatic block duration",
	)

	csvPath := flag.String(
		"csv",
		"",
		"Optional path for feature CSV",
	)

	label := flag.Int(
		"label",
		-1,
		"CSV label: 0 benign, 1 lab attack, -1 unknown",
	)

	runID := flag.String(
		"run-id",
		"",
		"CSV experiment identifier",
	)

	flag.Parse()

	// -------- Validate our configuration --------

	if os.Geteuid() != 0 {
		log.Fatal("Run with sudo")
	}

	if *detector != "off" &&
		*detector != "rules" &&
		*detector != "tree" {
		log.Fatal(
			"-detector must be off, rules, or tree",
		)
	}

	if *detector == "tree" && !treeTrained {
		log.Fatal(
			"No trained tree yet; train the model first",
		)
	}

	if *ppsThreshold <= 0 ||
		*minSamples <= 0 ||
		*autoTTL <= 0 {
		log.Fatal(
			"Threshold, min-samples and auto-ttl must be positive",
		)
	}

	if *label < -1 || *label > 1 {
		log.Fatal("-label must be -1, 0, or 1")
	}

	if *csvPath != "" && *runID == "" {
		log.Fatal(
			"Provide -run-id when using -csv",
		)
	}

	// -------- Set up graceful shutdown --------

	ctx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stop()

	// -------- Load the BPF program and maps --------

	var objs shieldObjects

	if err := loadShieldObjects(
		&objs, nil,
	); err != nil {
		log.Fatalf(
			"Load BPF objects: %v", err,
		)
	}
	defer objs.Close()

	// Optional initial manual rule.
	if *staticBlock != "" {
		if err := addBlock(
			objs.Blocklist,
			*staticBlock,
			*ttl,
		); err != nil {
			log.Fatalf(
				"Initial block: %v", err,
			)
		}
	}

	// -------- Find the network interface --------

	iface, err := net.InterfaceByName(*ifaceName)

	if err != nil {
		log.Fatalf(
			"Find interface %q: %v",
			*ifaceName, err,
		)
	}

	// -------- Select the XDP attachment mode --------

	var attachFlags link.XDPAttachFlags

	switch *mode {
	case "driver":
		attachFlags = link.XDPDriverMode

	case "generic":
		attachFlags = link.XDPGenericMode

	default:
		log.Fatal(
			"-mode must be driver or generic",
		)
	}

	// -------- Attach the kernel XDP program --------

	xdpLink, err := link.AttachXDP(
		link.XDPOptions{
			Program:   objs.XdpShield,
			Interface: iface.Index,
			Flags:     attachFlags,
		},
	)

	if err != nil {
		log.Fatalf(
			"Attach XDP: %v", err,
		)
	}
	defer xdpLink.Close()

	// -------- Open kernel ring-buffer reader --------

	reader, err := ringbuf.NewReader(objs.Events)

	if err != nil {
		log.Fatalf(
			"Open ring buffer: %v", err,
		)
	}

	// -------- Build the Day 2 monitor config --------

	cfg := monitorConfig{
		Mode:         *detector,
		PPSThreshold: *ppsThreshold,
		MinSamples:   *minSamples,
		AutoTTL:      *autoTTL,
		CSVPath:      *csvPath,
		Label:        *label,
		RunID:        *runID,
	}

	log.Printf(
		"Shield attached: iface=%s xdp_mode=%s detector=%s",
		*ifaceName,
		*mode,
		*detector,
	)

	// Two workers must finish before shutdown.
	var wg sync.WaitGroup
	wg.Add(2)

	// Worker 1: read packet counters every second.
	go func() {
		defer wg.Done()

		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return

			case <-ticker.C:
				printStats(objs.Stats)
			}
		}
	}()

	// Worker 2: read samples and run detection.
	go func() {
		defer wg.Done()

		runMonitor(
			ctx,
			reader,
			objs.Blocklist,
			cfg,
		)
	}()

	// Worker 3: retain manual commands.
	go interactive(objs.Blocklist, stop)

	// Wait for quit, Ctrl+C, or SIGTERM.
	<-ctx.Done()

	// Stop event reading and wait for workers.
	_ = reader.Close()
	wg.Wait()

	log.Println(
		"Shield stopping; XDP link will be detached",
	)
}
