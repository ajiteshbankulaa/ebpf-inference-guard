# eBPF Inference Guard

An experimental Linux traffic guard built with XDP/eBPF and Go. The kernel program samples IPv4 packet metadata, while a Go process aggregates traffic features, applies optional detection, and manages a temporary source-IP blocklist.

> **Scope:** despite the project name, the current version does not parse inference requests or application payloads. It is a network-layer prototype that classifies traffic using packet metadata. Treat the detection and training results as lab experiments, not production protection.

## How it works

```text
Ethernet / IPv4 packets
        |
        v
XDP program (bpf/shield.bpf.c)
  - enforce IPv4 source blocklist
  - sample about 1 in 64 allowed IPv4 packets
  - send metadata through a BPF ring buffer
        |
        v
Go controller (cmd/shield)
  - aggregate samples by source IP in 1-second windows
  - calculate PPS, TCP SYN ratio, mean packet size, and IAT CV
  - print counters and optionally write labelled CSV rows
  - optionally detect and temporarily block a source IP
        |
        v
CSV windows -> Python training (ml/train.py)
  - train/evaluate a shallow decision tree by experiment run
  - export the trained tree as Go source
```

### Current behavior and limits

- XDP runs on ingress for the selected interface. IPv4 source-address rules are checked before telemetry sampling.
- Non-IPv4 packets pass through. Malformed IPv4 packets also pass and increment a counter.
- The blocklist holds up to 65,536 entries. A zero TTL means the rule lasts until it is removed or the process exits.
- Allowed IPv4 traffic is sampled randomly at approximately 1/64. PPS is estimated from those samples; low-rate estimates are noisy.
- The `rules` detector blocks only when estimated PPS is above its threshold **and** TCP SYN ratio is above 0.60. The default threshold is 25,000 PPS; tune it for a controlled lab and workload.
- The `tree` detector calls Go code generated from the training data. The checked-in sample data is small and lab-specific; an evaluation on held-out runs is not evidence of production accuracy.
- Detection defaults to `off`. `rules` and `tree` can automatically block traffic, so start in an isolated lab and use an interface you can safely disrupt.
- Kernel maps are not pinned. Rules and counters are lost when the process exits.

## Requirements

For building and running the guard:

- Linux with XDP and BPF ring buffer support (Linux 5.8 or newer is recommended).
- Go 1.27.2 or newer, as declared in `go.mod`.
- Clang/LLVM with the BPF target and `llvm-strip`.
- GCC, Linux headers, and libbpf headers for `bpf2go` code generation.
- Root privileges to load the program and attach it to a network interface.

For training the decision tree:

- Python 3.12 or newer.
- Python packages pinned in [`ml/requirements.txt`](ml/requirements.txt).

On Debian or Ubuntu, install the system build dependencies with:

```sh
sudo apt update
sudo apt install -y clang llvm gcc libbpf-dev linux-libc-dev
sudo apt install -y linux-headers-$(uname -r)
```

## Build and check

Run these commands from the repository root. The generation step compiles the C program for both BPF byte orders, writes Go bindings, and creates local `.o` files required by the generated Go source. Object files are ignored by Git, so regenerate them after a fresh clone.

```sh
go generate ./cmd/shield
go test ./...
mkdir -p bin
go build -o bin/shield ./cmd/shield
```

Show the command-line flags:

```sh
./bin/shield -h
```

## Run the guard

First identify a test interface:

```sh
ip -br link
```

Start in observation mode. Generic XDP is usually more compatible; driver mode may perform better when the network driver supports it.

```sh
sudo ./bin/shield -iface veth-v -mode generic -detector off
```

The default interface is `veth-v`; replace it with an interface that exists in your environment. The program prints counters and per-source traffic windows about once per second. Press Ctrl+C or enter `quit` to detach and exit.

### Manual block and unblock

While the program is running, enter commands in its terminal:

```text
block 10.200.1.2 30s   # Block for 30 seconds
block 10.200.1.2       # Block until removed or process exit
unblock 10.200.1.2     # Remove the rule
quit                   # Detach and exit
```

Durations use Go syntax such as `30s`, `5m`, or `1h`. Manual commands accept IPv4 addresses only.

### Seed a block at startup

```sh
sudo ./bin/shield \
  -iface veth-v \
  -mode generic \
  -static-block 10.200.1.2 \
  -ttl 5m
```

`-ttl 0` (the default) creates a rule that lasts for the process lifetime.

## Detection modes

The default `-detector off` mode observes traffic without automatic blocks. Detection modes can block source addresses for `-auto-ttl` (default `30s`).

Rule-based detector:

```sh
sudo ./bin/shield \
  -iface veth-v \
  -mode generic \
  -detector rules \
  -pps-threshold 25000 \
  -min-samples 12 \
  -auto-ttl 30s
```

The rule triggers when both the estimated PPS threshold and a SYN ratio above `0.60` are met. Choose a threshold using representative benign and attack traffic from your lab; the default is only a starting value.

Decision-tree detector:

```sh
sudo ./bin/shield \
  -iface veth-v \
  -mode generic \
  -detector tree \
  -min-samples 5 \
  -auto-ttl 30s
```

The detector uses `cmd/shield/model_generated.go`. It is generated from your labelled CSV by the training steps below. Review the held-out-run evaluation and generated rule before enabling automatic blocking.

## Collect labelled training data

CSV collection is optional. The program appends one feature row per source IP per one-second window. Each CSV run needs a unique `-run-id`; labels are `0` for benign lab traffic, `1` for a controlled lab attack, and `-1` for unknown/unlabelled observations.

Start a separate process for each experiment run. For example, collect a benign run with detection disabled:

```sh
sudo ./bin/shield \
  -iface veth-v \
  -mode generic \
  -detector off \
  -csv data/windows.csv \
  -label 0 \
  -run-id benign_03
```

Generate benign traffic in the isolated lab, then stop the process with Ctrl+C. Repeat with a new run ID for each run. For controlled attack-labelled data, use `-label 1` and a distinct ID such as `attack_03`; generate that traffic only in a network you own or are authorized to test. Collect multiple independent runs for each label. Unknown observations can use `-label -1`, but the trainer excludes them.

The trainer requires at least two distinct run IDs for each of labels 0 and 1. It holds out the last sorted run for each class, trains on the remaining runs, prints a confusion matrix and classification report, then overwrites the generated Go model.

## Train and export the tree

Install the Python dependencies in a local virtual environment:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r ml/requirements.txt
```

Train and evaluate using the included sample dataset:

```sh
python ml/train.py \
  --csv data/windows.csv \
  --output cmd/shield/model_generated.go \
  --min-samples 5
```

The script splits by `run_id` (rather than randomly splitting adjacent windows), reports held-out metrics, and exports a shallow decision tree as ordinary Go conditionals. After training, rebuild the application:

```sh
gofmt -w cmd/shield/model_generated.go
go test ./...
go build -o bin/shield ./cmd/shield
```

For another dataset, pass its path with `--csv`. The CSV must contain `pps`, `syn_ratio`, `mean_packet_bytes`, `iat_cv`, `label`, `run_id`, and `samples`. Use at least two separate runs per class; more varied runs are needed for meaningful evaluation.

## Command-line options

| Flag | Default | Description |
| --- | --- | --- |
| `-iface` | `veth-v` | Interface where XDP attaches. |
| `-mode` | `driver` | XDP mode: `driver` or `generic`. |
| `-static-block` | none | Optional IPv4 address to block on startup. |
| `-ttl` | `0` | Initial block duration; zero means until removal or process exit. |
| `-detector` | `off` | Detector: `off`, `rules`, or `tree`. |
| `-pps-threshold` | `25000` | Minimum estimated PPS for the rules detector. |
| `-min-samples` | `12` | Minimum sampled packets in a window before detection. |
| `-auto-ttl` | `30s` | Duration of automatic blocks; must be positive. |
| `-csv` | none | Optional output CSV path; requires `-run-id`. |
| `-label` | `-1` | CSV label: `0` benign, `1` controlled lab attack, `-1` unknown. |
| `-run-id` | none | Experiment identifier required when writing CSV. |

## Project layout

```text
bpf/shield.bpf.c                 XDP program and kernel maps
cmd/shield/main.go               Go loader, CLI, block controls, counters
cmd/shield/telemetry.go          Event reader, feature windows, detection, CSV
cmd/shield/gen.go                bpf2go generation directive
cmd/shield/shield_bpf*.go        Generated Go bindings and embedded BPF objects
cmd/shield/telemetry_test.go     Feature and event conversion tests
cmd/shield/model_generated.go    Generated decision-tree predictor
data/windows.csv                Sample labelled lab dataset
ml/train.py                     Training, evaluation, and Go export
ml/requirements.txt             Pinned Python dependencies
```

## Troubleshooting

- **Interface lookup failed:** use `ip -br link` and pass an existing interface with `-iface`.
- **Driver attach is unsupported:** try `-mode generic`.
- **BPF load or permission error:** run with `sudo` and check the running kernel's BPF/XDP support.
- **`go build` cannot find an embedded `.o` file:** run `go generate ./cmd/shield` first.
- **`go generate` cannot find a compiler or header:** install Clang/LLVM, GCC, Linux headers, and libbpf headers.
- **The tree trainer reports too few runs:** add at least two separate `run_id` values for both label 0 and label 1.

## References

- [Cilium eBPF Go getting-started guide](https://github.com/cilium/ebpf/blob/main/docs/ebpf/guides/getting-started.md)
- [Linux BPF ring buffer documentation](https://docs.kernel.org/bpf/ringbuf.html)
