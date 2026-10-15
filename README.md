# eBPF Inference Guard

An experimental Linux traffic guard built with XDP/eBPF and Go. The kernel program samples IPv4 packet metadata, while a Go process aggregates traffic features, applies optional detection, and manages a temporary source-IP blocklist.

> **Scope:** the XDP program does not parse inference requests or application payloads. The separate admission gateway is an L7 example that estimates request cost after TLS termination; it does not run inference or share block policy with the node agent. Treat detection and training results as lab experiments, not production protection.

## Engineering scope

This repository brings together Linux kernel programming in C, a Go eBPF controller, Kubernetes deployment, Terraform-managed AWS infrastructure, offline model training, and an L7 request admission example. The recorded AWS exercise used an EKS worker and NLB; local development uses disposable network namespaces. The AWS stack was torn down after validation. It is a compact systems project for discussing dataplane boundaries, deployment safety, telemetry, and reproducible validation.

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

The optional admission gateway is a separate L7 signal path:

```text
client -> TLS termination -> admission gateway -> request budget decision
              |
              +-> encrypted network packets -> XDP sees L2-L4 metadata only
```

The gateway and node agent expose Prometheus metrics. The gateway sees prompt fields only after TLS termination; XDP does not inspect model requests or prompt text.

### Current behavior and limits

- XDP runs on ingress for the selected interface. If `-iface` is omitted, the controller selects the interface on the lowest-metric IPv4 default route. Set `-iface` explicitly in labs or when protecting a non-default interface. IPv4 source-address rules are checked before telemetry sampling.
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

The GitHub Actions workflow regenerates and verifies the checked-in Go tree from the sample dataset, then runs Go tests, vet, builds both commands and the container, smoke-tests both CLIs, validates Terraform formatting/configuration, checks Kubernetes YAML structure, and tests the benchmark helpers on pushes and pull requests. The model check is a small reproducible train/evaluate/export step; it does not use a managed training service or claim production model quality.

## Run the guard

For cloud or host deployment, confirm the selected interface before starting the process. The default is the interface on the lowest-metric IPv4 default route. Pass `-iface` explicitly to override it.

For isolated development, identify a test interface:

```sh
ip -br link
```

Start in observation mode on a disposable interface. Driver mode requests native XDP; generic mode requests XDP in the kernel's SKB path. Select the mode deliberately and validate it on that interface first.

```sh
sudo ./bin/shield -iface veth-v -mode generic -detector off
```

The example interface `veth-v` must exist in your environment. The program prints counters and per-source traffic windows about once per second. Press Ctrl+C or enter `quit` to detach and exit.

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

## Admission gateway

`cmd/gateway` is a small L7 admission example. It accepts `POST /v1/admit` with a JSON body such as:

```json
{"model":"example-model","prompt":"Summarize this report.","max_tokens":8192}
```

It returns an allow/reject decision and reports request bytes, estimated input tokens, requested output tokens, concurrent requests, and a configurable cost score. Input tokens are estimated as UTF-8 prompt bytes divided by four; this is a rough budget signal, not tokenizer output. The service does not call a model provider. Tenant IDs come from `X-Tenant-ID`; source IP comes from the socket peer, and forwarded headers are not trusted by default. Metric label cardinality is capped so arbitrary tenant and address values cannot grow it without bound.

Run locally with `go run ./cmd/gateway`. The request port is 8080 and metrics are served at `http://127.0.0.1:9101/shield/metrics`. Example request:

```sh
curl -X POST http://127.0.0.1:8080/v1/admit \
  -H 'Content-Type: application/json' -H 'X-Tenant-ID: demo' \
  --data '{"model":"example-model","prompt":"hello","max_tokens":128}'
```

The gateway makes an L7 admission decision; it does not publish a block to the node agent's BPF map. The node agent's network detector remains a separate signal path. Combining those decisions and distributing blocks to every worker requires an authenticated policy service or controller and is future work; the current deployment does not imply cross-layer or multi-node synchronization.

## Prometheus metrics

The node agent serves `/shield/metrics` on `-metrics-addr` (default `127.0.0.1:9100`). It reports packet pass/drop/malformed totals, ring-buffer events and loss, active block entries, detector decisions, and detection-to-map-update latency. The gateway serves request, request-size, token-estimate, concurrency, tenant, and source-IP metrics on port 9101. Kubernetes manifests expose these through cluster-internal `ClusterIP` Services. The endpoint is not an authentication boundary; restrict network access if you change the bind address.

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

The script splits by `run_id` (rather than randomly splitting adjacent windows), reports held-out metrics, and exports a shallow decision tree as ordinary Go conditionals. CI reruns this flow against the checked-in sample windows and checks that the generated Go matches the committed artifact. This is a reproducibility check on a small lab dataset, not a production model-quality claim. After training, rebuild the application:

```sh
gofmt -w cmd/shield/model_generated.go
go test ./...
go build -o bin/shield ./cmd/shield
```

For another dataset, pass its path with `--csv`. The CSV must contain `pps`, `syn_ratio`, `mean_packet_bytes`, `iat_cv`, `label`, `run_id`, and `samples`. Use at least two separate runs per class; more varied runs are needed for meaningful evaluation.

## Command-line options

| Flag | Default | Description |
| --- | --- | --- |
| `-iface` | IPv4 default route | Interface where XDP attaches. |
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
| `-metrics-addr` | `127.0.0.1:9100` | Prometheus bind address for `/shield/metrics`; empty disables the endpoint. |

## Project layout

```text
bpf/shield.bpf.c                 XDP program and kernel maps
cmd/shield/main.go               Go loader, CLI, block controls, counters
cmd/shield/telemetry.go          Event reader, feature windows, detection, CSV
cmd/shield/gen.go                bpf2go generation directive
cmd/shield/shield_bpf*.go        Generated Go bindings and embedded BPF objects
cmd/shield/telemetry_test.go     Feature and event conversion tests
cmd/shield/model_generated.go    Generated decision-tree predictor
cmd/shield/metrics.go            Prometheus metrics for XDP and telemetry
cmd/gateway/                     L7 request admission example and metrics
data/windows.csv                Sample labelled lab dataset
ml/train.py                     Training, evaluation, and Go export
ml/requirements.txt             Pinned Python dependencies
deploy/terraform/               EKS, VPC, ECR, and controller IAM resources
deploy/kubernetes/               Namespace, echo service, gateway, shield, metrics
scripts/benchmark/                Measurement protocol and CSV summarizer
```

## Troubleshooting

- **Interface lookup failed:** use `ip -br link` and pass an existing interface with `-iface`.
- **XDP attach returns `invalid argument`:** check `journalctl -k` as well as the interface index, MTU, requested mode, and existing attachments (`ip -details link show dev IFACE` and `bpftool net`). On the tested ENA worker the kernel log gives the precise cause: MTU 9001 exceeds native XDP's 3502-byte limit for this program. This project uses BPF-link attachment. Driver mode requests native XDP; generic mode runs in the SKB path after packet-buffer allocation. Test changes on a disposable interface before touching a live one.
- **BPF load or permission error:** run with `sudo` and check the running kernel's BPF/XDP support.
- **`go build` cannot find an embedded `.o` file:** run `go generate ./cmd/shield` first.
- **`go generate` cannot find a compiler or header:** install Clang/LLVM, GCC, Linux headers, and libbpf headers.
- **The tree trainer reports too few runs:** add at least two separate `run_id` values for both label 0 and label 1.

## AWS EKS deployment and verified results

The `ebpf-shield` cluster in `us-east-1` ran the nginx test service behind an internet-facing NLB and the Shield agent as a privileged, node-selectable DaemonSet. The gateway and both metrics services were ClusterIP-only. Keep the agent detector set to `off` for a new cloud observation run. The node label `shield.example.com/eligible=true` selects the worker; remove it to stop the DaemonSet on that node.

On 2026-10-14, the EKS worker (`ip-10-0-2-119`, Amazon Linux 2023, kernel 6.18.51, ENA 2.17.2g) rejected the agent's `mode=driver` BPF-link request with `BPF_LINK_CREATE: invalid argument`. A later read-only check of the worker's kernel log found the reason: `Failed to set xdp program, the current MTU (9001) is larger than the maximum allowed MTU (3502) while xdp is on`. The XDP program loaded; the rejection came from ENA during native attachment. `bpftool net show` showed no pre-existing XDP program at the time of the original attempt. This is a jumbo-MTU constraint for the tested program and driver setup, not proof that ENA lacks native XDP or that BPF links are inherently incompatible. Amazon's [ENA driver documentation](https://github.com/amzn/amzn-drivers/blob/master/kernel/linux/ena/README.rst) describes the single-buffer MTU limit and the `BPF_F_XDP_HAS_FRAGS` option for multi-buffer XDP. Neither reducing the EKS interface MTU nor enabling multi-buffer support was tested here; both need a separate controlled validation before claiming native protection. Changing the worker MTU could affect Kubernetes traffic and is not part of this deployment.

For the working cloud demonstration, the DaemonSet explicitly requests `mode=generic` on `enp39s0`. This is generic XDP in the kernel SKB path, not native ENA/driver XDP. Independent verification with `bpftool net show` reported `enp39s0 generic`, program ID 340, name `xdp_shield`; `ip -details link` showed `xdpgeneric`. A safe stop and restart using the eligibility label removed the owned attachment and recreated it. The agent remained at 1/1 Ready with zero restarts after the generic-mode rollout. Detector mode remained `off`.

Eight low-rate requests to the existing NLB returned HTTP 200 with nginx. AWS reported the NLB active and its worker target healthy. During these requests, Shield reported 429 passed packets, 7 ring-buffer events, and 0 ring-buffer events lost; sampled flow windows included the test client address `129.161.212.42` and private addresses from the EKS path. This demonstrates observation of the tested NLB traffic at the generic XDP hook.

A second bounded run on 2026-10-14 sent HTTP GETs through that same NLB for 60 seconds, using four clients capped at 20 requests per second each. It completed 4,158 requests (69.25 requests/second) with 4,158 HTTP 200 responses and no client errors. End-to-end latency was 16.42 ms at p50, 27.79 ms at p95, and 56.12 ms at p99 (182.22 ms maximum). Over the same observation window, the agent's passed-packet counter rose from 4,760 to 13,656; ring-buffer events rose from 90 to 238, with zero events lost. This is a small service-path smoke measurement: it includes the client, NLB, and application path, and does not isolate XDP cost or measure packet throughput.

The gateway was exercised through its Kubernetes Service. A small request was admitted with HTTP 200; a request asking for 8,192 output tokens scored 2,061 against the configured 2,000 budget and was rejected with HTTP 429. Gateway metrics recorded request size, estimated input tokens, and tenant/source labels. Token estimates use UTF-8 bytes divided by four; they are a rough admission heuristic, not tokenizer output. The gateway does not run inference and does not synchronize its decisions to the XDP block map.

The immutable ECR image deployed for this validation is `296062591117.dkr.ecr.us-east-1.amazonaws.com/ebpf-shield:build-day4-20261014-2348z`, digest `sha256:8ba21d6771514e667e759bf5a55ba73865810c05534c4c25a06e1cf8d1344c34`. The same image is referenced by the shield and gateway manifests. Keep the `-detector off` argument when applying the DaemonSet.

### Deploy and inspect

The committed manifests contain the image used in this run. Review the selected interface and mode before applying them to another cluster.

```sh
kubectl apply -f deploy/kubernetes/namespace.yaml
kubectl apply -f deploy/kubernetes/shield-agent.yaml
kubectl apply -f deploy/kubernetes/shield-metrics.yaml
kubectl apply -f deploy/kubernetes/gateway.yaml
kubectl rollout status daemonset/shield-agent -n shield-system
kubectl rollout status deployment/shield-gateway -n shield-system
kubectl get pods,svc -n shield-system
```

Check XDP independently on the worker with `sudo bpftool net show` and `sudo ip -details link show dev enp39s0`. Metrics are available at `/shield/metrics` on port 9100 for the agent and 9101 for the gateway. Do not infer attachment from Pod readiness. Removing eligibility is the supported stop path; confirm `bpftool net show` no longer lists Shield's program ID. The agent owns its BPF link and closes it on shutdown.

For a fresh image, build and push a new immutable tag. ECR tag immutability prevents reusing the published tag above.

```sh
TAG="git-$(git rev-parse --short HEAD)-$(date -u +%Y%m%d%H%M%S)"
REGION=us-east-1
ACCOUNT_ID="$(aws sts get-caller-identity --profile ebpf-lab --query Account --output text)"
IMAGE="$ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com/ebpf-shield:$TAG"
aws ecr get-login-password --profile ebpf-lab --region "$REGION" | docker login --username AWS --password-stdin "$ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com"
docker build -t "$IMAGE" .
docker run --rm "$IMAGE" -h
docker push "$IMAGE"
```

Update both the shield and gateway image fields to the pushed reference before applying their manifests. Replace the reserved test CIDR `192.0.2.0/24` in `echo.yaml` with the trusted client range before using that manifest. The test NLB was restricted to `129.161.212.42/32`; retain a narrow source range in a new deployment.

### Benchmark status

The first packet-path comparison used a disposable veth pair on the existing EKS worker, with five 100,000-packet runs per case after a warm-up. Median measured ingress completion rates were 415,445 pps for unfiltered PASS, 1,163,581 pps for Shield generic-XDP drop, 489,237 pps for nftables drop, and 376,279 pps for Shield generic XDP with sampled telemetry; the telemetry case recorded 7,891 events and no ring-buffer loss. The [run notes](scripts/benchmark/worker-veth-2026-10-14.md) include the raw [CSV](scripts/benchmark/worker-veth-2026-10-14.csv), setup, and limits. This same-worker veth test is a small software-path comparison, not ENA throughput: the generator shared the worker CPU, and victim CPU/cycles were not measured. The separate direct-VPC protocol below remains unrun, so do not present these rates as cloud NIC performance.

The repository also includes a repeatable direct private-VPC protocol and CSV summarizer under [`scripts/benchmark/`](scripts/benchmark/README.md), with five repetitions each for PASS, XDP DROP, nftables DROP, and XDP with telemetry. That experiment avoids the NLB path and measures packets, victim CPU, cycles, instructions, and ring-buffer loss. The dedicated traffic-generator EC2 instance was not provisioned. The bounded NLB request run above checks application reachability, latency under a small request load, and concurrent XDP observation; it is not a dataplane benchmark.

The verified cloud datapath uses generic XDP. Native ENA attachment is blocked by the worker's 9001-byte MTU with this single-buffer program; there is no claim of native-XDP protection. A future native test should use a disposable ENA interface with an approved lower MTU or a separately verified multi-buffer program, then measure the real NIC path. Do not replace an attachment the process does not own.

Terraform state and variables are local operational files and are ignored by Git. Preserve the state while its AWS resources exist. AWS resources including EKS, EC2, NAT gateways, ECR storage, and the NLB can incur charges. When finished, inspect the Terraform plan using the matching state, then destroy only resources represented by that reviewed plan. Removing a Kubernetes LoadBalancer Service deletes its managed NLB.

**Teardown recorded October 14, 2026 (US Eastern):** the `echo-nlb` Service was deleted first, then a reviewed Terraform destroy removed 63 resources. Follow-up checks found no EKS cluster, EC2 instance, EBS volume, NAT gateway, Elastic IP, load balancer, ECR repository, S3 bucket, or retained CloudWatch log group in this account. Terraform state is empty but kept locally for audit. The EKS KMS key is pending deletion on November 14; [AWS does not charge for customer-managed keys scheduled for deletion](https://aws.amazon.com/kms/pricing/). The old NLB URL and ECR image references above are records of the run, not live endpoints.

## References

- [Cilium eBPF Go getting-started guide](https://github.com/cilium/ebpf/blob/main/docs/ebpf/guides/getting-started.md)
- [Linux BPF ring buffer documentation](https://docs.kernel.org/bpf/ringbuf.html)
