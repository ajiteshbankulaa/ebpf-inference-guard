#!/usr/bin/env python3
"""Summarize repeated dataplane measurements from a CSV file."""

import argparse
import csv
import statistics
import sys
from collections import defaultdict

REQUIRED = {
    "configuration",
    "repetition",
    "attach_mode",
    "packet_size_bytes",
    "duration_seconds",
    "packets",
    "victim_cpu_percent",
    "cycles",
    "instructions",
    "ringbuf_lost",
}
CONFIGURATIONS = ("pass", "xdp_drop", "nftables_drop", "xdp_telemetry")


def summarize(path, minimum_repetitions=5):
    with open(path, newline="", encoding="utf-8") as source:
        reader = csv.DictReader(source)
        missing = REQUIRED - set(reader.fieldnames or ())
        if missing:
            raise ValueError(f"CSV is missing columns: {', '.join(sorted(missing))}")
        rows = defaultdict(list)
        seen = set()
        attach_modes = defaultdict(set)
        packet_sizes = set()
        durations = set()
        for line, row in enumerate(reader, 2):
            case = row["configuration"].strip()
            if case not in CONFIGURATIONS:
                raise ValueError(f"line {line}: unknown configuration {case!r}")
            key = (case, row["repetition"].strip())
            if key in seen:
                raise ValueError(f"line {line}: duplicate run {key}")
            seen.add(key)
            try:
                duration = float(row["duration_seconds"])
                packets = int(row["packets"])
                cpu = float(row["victim_cpu_percent"])
                cycles = int(row["cycles"])
                instructions = int(row["instructions"])
                lost = int(row["ringbuf_lost"])
                packet_size = int(row["packet_size_bytes"])
            except (TypeError, ValueError) as exc:
                raise ValueError(f"line {line}: invalid numeric field: {exc}") from exc
            if duration <= 0 or packet_size <= 0 or packets < 0 or cpu < 0 or cycles < 0 or instructions < 0 or lost < 0:
                raise ValueError(f"line {line}: values must be nonnegative and duration positive")
            attach_mode = row["attach_mode"].strip().lower()
            if case.startswith("xdp_") and attach_mode not in ("native", "generic"):
                raise ValueError(f"line {line}: XDP cases must record native or generic attach_mode")
            if not case.startswith("xdp_") and attach_mode != "none":
                raise ValueError(f"line {line}: non-XDP cases must use attach_mode=none")
            packet_sizes.add(packet_size)
            durations.add(duration)
            attach_modes[case].add(attach_mode)
            if case != "xdp_telemetry" and lost != 0:
                raise ValueError(f"line {line}: ringbuf_lost applies only to xdp_telemetry")
            rows[case].append({
                "pps": packets / duration,
                "cpu": cpu,
                "cycles_per_packet": cycles / packets if packets else 0,
                "instructions_per_packet": instructions / packets if packets else 0,
                "loss": lost,
            })

    for case in CONFIGURATIONS:
        count = len(rows[case])
        if count < minimum_repetitions:
            raise ValueError(f"{case}: found {count} runs; need at least {minimum_repetitions}")
    if len(packet_sizes) != 1:
        raise ValueError("packet_size_bytes must be identical across all configurations")
    if len(durations) != 1:
        raise ValueError("duration_seconds must be identical across all configurations")
    for case, modes in attach_modes.items():
        if len(modes) != 1:
            raise ValueError(f"{case}: do not combine attachment modes in one summary")

    lines = ["configuration,repetitions,attach_mode,packet_size_bytes,duration_seconds,pps_median,pps_min,pps_max,cpu_pct_median,cycles_per_packet_median,instructions_per_packet_median,ringbuf_lost_median"]
    for case in CONFIGURATIONS:
        sample = rows[case]
        attach_mode = next(iter(attach_modes[case]))
        fields = [
            case,
            str(len(sample)),
            attach_mode,
            str(next(iter(packet_sizes))),
            f"{next(iter(durations)):.2f}",
            f"{statistics.median(r['pps'] for r in sample):.2f}",
            f"{min(r['pps'] for r in sample):.2f}",
            f"{max(r['pps'] for r in sample):.2f}",
            f"{statistics.median(r['cpu'] for r in sample):.2f}",
            f"{statistics.median(r['cycles_per_packet'] for r in sample):.2f}",
            f"{statistics.median(r['instructions_per_packet'] for r in sample):.2f}",
            f"{statistics.median(r['loss'] for r in sample):.2f}",
        ]
        lines.append(",".join(fields))
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("csv", help="measurements CSV; this tool never creates or fills measurements")
    parser.add_argument("--minimum-repetitions", type=int, default=5)
    args = parser.parse_args()
    try:
        print(summarize(args.csv, args.minimum_repetitions))
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
