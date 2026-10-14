# Dataplane benchmark protocol

This benchmark compares the dataplane on a single EKS worker. It is separate from the NLB HTTP check. The NLB adds variables that make it unsuitable for measuring the packet hook itself.

## Topology and safety

Use a dedicated, temporary traffic-generator EC2 instance in the same VPC and send traffic directly to the worker's private address. Keep the experiment on an isolated test port and a disposable test service. Do not point a packet generator at a shared or public service. A new generator instance adds AWS cost; this repository does not create one automatically.

The worker's primary ENA interface and its kernel belong to EKS. Inspect current attachments and get operational approval before changing live XDP or nftables state. Never detach an attachment you do not own. Run PASS, XDP_DROP, nftables DROP, and XDP with telemetry with the same kernel, instance types, generator, destination, packet size, duration, CPU allocation, and software revision. Verify each configuration before recording it. Keep detector mode off.

`link.AttachXDP` is used for the XDP runs. Record whether the attachment is driver or generic mode; never combine results from different modes in one row. For each case, run at least five repetitions after a warm-up. Collect packets sent/received on the generator, victim CPU utilization with `mpstat -P ALL 1`, cycles and instructions from the victim with `perf stat`, XDP counters, and ring-buffer loss. Use the same packet size (for example, 64 bytes) across configurations. Record each run, not an average, in a CSV with this header:

```csv
configuration,repetition,attach_mode,packet_size_bytes,duration_seconds,packets,victim_cpu_percent,cycles,instructions,ringbuf_lost
```

For XDP and nftables DROP, count packets at the generator or on the victim ingress before the drop hook. Do not use the shield's pass counter as a receive-rate measure for dropped packets. Keep raw command output with the run artifacts. Calculate PPS as packets divided by duration; the summarizer reports medians and min/max across repetitions and median CPU, cycles per packet, instruction per packet, and ring-buffer loss.

```sh
python3 scripts/benchmark/summarize.py measurements.csv
```

The summarizer requires five rows for each configuration by default and fails on incomplete or malformed data. No benchmark results are checked in until the experiment has actually been run and its environment recorded.
