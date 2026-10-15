#!/usr/bin/env python3
"""Run a fixed-count burst and time its arrival at the disposable veth."""

import argparse
import subprocess
import time
from pathlib import Path


RX_COUNTER = Path("/sys/class/net/bench-host/statistics/rx_packets")


def rx_packets():
    return int(RX_COUNTER.read_text(encoding="ascii").strip())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("packet_count", type=int)
    parser.add_argument("--timeout", type=float, default=10.0)
    args = parser.parse_args()
    if args.packet_count <= 0 or args.timeout <= 0:
        parser.error("packet-count and timeout must be positive")

    before = rx_packets()
    started = time.perf_counter()
    result = subprocess.run(
        ["ip", "netns", "exec", "shieldbench", "/tmp/shield-udp-burst", str(args.packet_count)],
        check=True,
        capture_output=True,
        text=True,
    )
    deadline = started + args.timeout
    received = 0
    while time.perf_counter() < deadline:
        received = rx_packets() - before
        if received >= args.packet_count:
            break
        time.sleep(0.001)
    elapsed = time.perf_counter() - started
    sender = result.stdout.strip().replace(" ", ",")
    print(
        f"expected_packets={args.packet_count},ingress_packets={received},completion_seconds={elapsed:.6f},"
        f"ingress_pps={received / elapsed:.2f},{sender}"
    )
    if received < args.packet_count:
        raise SystemExit(f"ingress shortfall: expected at least {args.packet_count}, observed {received}")


if __name__ == "__main__":
    main()
