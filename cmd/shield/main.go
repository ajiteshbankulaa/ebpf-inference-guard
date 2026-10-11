
package main

import (
    "bufio"
    "bytes"
    "context"
    "encoding/binary"
    "errors"
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

// Must match struct block_entry in the C program.
type blockEntry struct {
    ExpiresNS uint64
    Reason    uint32
    Reserved  uint32
}

// Must match struct counters in the C program.
type counterValue struct {
    Pass        uint64
    Drop        uint64
    Malformed   uint64
    RingbufLost uint64
}

// Must match struct packet_event.
// IP is stored as raw network-order bytes.
type packetEvent struct {
    TimestampNS uint64
    SrcIP       [4]byte
    Action      uint32
}

// Add an IPv4 address to the kernel blocklist.
func addBlock(m *ebpf.Map, address string, ttl time.Duration) error {
    ip, err := netip.ParseAddr(address)
    if err != nil || !ip.Is4() {
        return fmt.Errorf("invalid IPv4 address: %s", address)
    }

    if ttl < 0 {
        return fmt.Errorf("TTL cannot be negative")
    }

    entry := blockEntry{
        Reason: 1,
    }

    if ttl > 0 {
        // Use CLOCK_MONOTONIC to match bpf_ktime_get_ns().
        var now unix.Timespec

        if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &now); err != nil {
            return err
        }

        currentNS := uint64(now.Sec)*1_000_000_000 +
            uint64(now.Nsec)

        entry.ExpiresNS = currentNS + uint64(ttl.Nanoseconds())
    }

    // As4() provides the four bytes in network order.
    key := ip.As4()

    return m.Update(key, entry, ebpf.UpdateAny)
}

// Remove an IPv4 address from the blocklist.
func removeBlock(m *ebpf.Map, address string) error {
    ip, err := netip.ParseAddr(address)
    if err != nil || !ip.Is4() {
        return fmt.Errorf("invalid IPv4 address: %s", address)
    }

    return m.Delete(ip.As4())
}

// Read per-CPU counters and sum across CPUs.
func printStats(m *ebpf.Map) {
    var perCPU []counterValue

    if err := m.Lookup(uint32(0), &perCPU); err != nil {
        log.Printf("stats lookup failed: %v", err)
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

// Read sampled events emitted by the kernel.
func readEvents(reader *ringbuf.Reader) {
    for {
        record, err := reader.Read()
        if err != nil {
            if errors.Is(err, os.ErrClosed) {
                return
            }

            log.Printf("ring buffer read failed: %v", err)
            return
        }

        var event packetEvent

        err = binary.Read(
            bytes.NewReader(record.RawSample),
            binary.NativeEndian,
            &event,
        )
        if err != nil {
            log.Printf("invalid event: %v", err)
            continue
        }

        ip := netip.AddrFrom4(event.SrcIP)

        log.Printf(
            "[EVENT] source=%s action=%d time_ns=%d",
            ip,
            event.Action,
            event.TimestampNS,
        )
    }
}

// Accept commands while the XDP program is running.
func interactive(m *ebpf.Map, stop context.CancelFunc) {
    scanner := bufio.NewScanner(os.Stdin)

    fmt.Println("Commands:")
    fmt.Println("  block 10.200.1.1 30s")
    fmt.Println("  block 10.200.1.1       (permanent)")
    fmt.Println("  unblock 10.200.1.1")
    fmt.Println("  quit")
    fmt.Println()

    for scanner.Scan() {
        parts := strings.Fields(scanner.Text())

        if len(parts) == 0 {
            continue
        }

        switch parts[0] {
        case "block":
            if len(parts) < 2 || len(parts) > 3 {
                fmt.Println("Usage: block <IPv4> [duration]")
                continue
            }

            ttl := time.Duration(0)

            if len(parts) == 3 {
                var err error
                ttl, err = time.ParseDuration(parts[2])
                if err != nil {
                    fmt.Printf("Invalid duration: %v\n", err)
                    continue
                }
            }

            if err := addBlock(m, parts[1], ttl); err != nil {
                fmt.Printf("Block failed: %v\n", err)
                continue
            }

            fmt.Printf("Blocked %s (TTL=%s)\n", parts[1], ttl)

        case "unblock":
            if len(parts) != 2 {
                fmt.Println("Usage: unblock <IPv4>")
                continue
            }

            err := removeBlock(m, parts[1])
            if err != nil {
                fmt.Printf("Unblock failed: %v\n", err)
                continue
            }

            fmt.Printf("Unblocked %s\n", parts[1])

        case "quit", "exit":
            stop()
            return

        default:
            fmt.Println("Unknown command. Use block, unblock, or quit.")
        }
    }

    if err := scanner.Err(); err != nil {
        log.Printf("terminal input error: %v", err)
    }
}

func main() {
    ifaceName := flag.String(
        "iface", "veth-v", "Network interface to protect",
    )

    mode := flag.String(
        "mode", "driver", "XDP mode: driver or generic",
    )

    staticBlock := flag.String(
        "static-block", "", "Optional initial IPv4 block",
    )

    ttl := flag.Duration(
        "ttl", 0, "Initial block duration (0 = permanent)",
    )

    flag.Parse()

    if os.Geteuid() != 0 {
        log.Fatal("Run as root using sudo")
    }

    ctx, stop := signal.NotifyContext(
        context.Background(),
        os.Interrupt,
        syscall.SIGTERM,
    )
    defer stop()

    var objs shieldObjects

    if err := loadShieldObjects(&objs, nil); err != nil {
        log.Fatalf("loading eBPF objects: %v", err)
    }
    defer objs.Close()

    if *staticBlock != "" {
        if err := addBlock(objs.Blocklist, *staticBlock, *ttl); err != nil {
            log.Fatalf("initial block failed: %v", err)
        }
    }

    iface, err := net.InterfaceByName(*ifaceName)
    if err != nil {
        log.Fatalf("interface lookup failed: %v", err)
    }

    var attachFlags link.XDPAttachFlags

    switch *mode {
    case "driver":
        attachFlags = link.XDPDriverMode
    case "generic":
        attachFlags = link.XDPGenericMode
    default:
        log.Fatal("mode must be driver or generic")
    }

    xdpLink, err := link.AttachXDP(link.XDPOptions{
        Program:   objs.XdpShield,
        Interface: iface.Index,
        Flags:     attachFlags,
    })
    if err != nil {
        log.Fatalf("attaching XDP: %v", err)
    }
    defer xdpLink.Close()

    reader, err := ringbuf.NewReader(objs.Events)
    if err != nil {
        log.Fatalf("opening ring buffer: %v", err)
    }

    log.Printf("Shield attached to %s in %s mode", *ifaceName, *mode)

    var wg sync.WaitGroup
    wg.Add(2)

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

    go func() {
        defer wg.Done()
        readEvents(reader)
    }()

    go interactive(objs.Blocklist, stop)

    <-ctx.Done()


    reader.Close()
    wg.Wait()

    log.Println("Shield stopping; XDP link will be detached")
}
