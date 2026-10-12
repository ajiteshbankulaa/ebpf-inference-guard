# eBPF Inference Guard

An experimental Linux XDP packet filter with a small Go control program. The current implementation blocks IPv4 source addresses using an in-kernel map, reports packet counters, and emits sampled drop events.

> **Current scope:** this version filters by IPv4 source address. It does not inspect inference requests, application payloads, or model traffic. Rules and counters live in kernel maps while the process is running; they are not persisted across restarts.

## What it does

- Attaches an XDP program to a network interface in driver or generic mode.
- Passes non-IPv4 traffic and malformed IPv4 packets. Malformed packets are counted.
- Drops IPv4 packets whose source address is in the blocklist, unless that entry's TTL has expired.
- Supports up to 65,536 blocklist entries.
- Prints aggregate pass, drop, malformed, and lost-event counters about once per second.
- Emits a log event for approximately every eighth dropped packet per CPU.
- Supports adding and removing IPv4 block entries while the program is running.

The XDP hook sees ingress traffic on the selected interface. Attach it only to an interface where filtering that traffic is intended.

## Requirements

- Linux with a kernel that supports XDP and BPF ring buffer maps (Linux 5.8 or newer is recommended).
- Go 1.27.2 or newer, matching the version declared in `go.mod`.
- Clang/LLVM with the BPF target, including `llvm-strip`.
- GCC, Linux headers, and libbpf headers for generating the eBPF bindings.
- Root privileges to load the BPF program and attach it to a network interface.

On Debian or Ubuntu, install the system build dependencies with:

```sh
sudo apt update
sudo apt install -y clang llvm gcc libbpf-dev linux-libc-dev
```

You may also need the headers for your running kernel:

```sh
sudo apt install -y linux-headers-$(uname -r)
```

## Build

Run these commands from the repository root. `go generate` compiles `bpf/shield.bpf.c` for little- and big-endian BPF targets and generates the Go bindings and local `.o` files. The generated Go files are tracked; the `.o` files are build artifacts and are ignored by Git.

```sh
go generate ./cmd/shield
mkdir -p bin
go build -o bin/shield ./cmd/shield
```

To see the available command-line flags:

```sh
./bin/shield -h
```

## Run

List the available interfaces and choose the one whose ingress traffic you intend to filter:

```sh
ip -br link
```

Attach in generic mode:

```sh
sudo ./bin/shield -iface <interface> -mode generic
```

For example, if your test interface is named `veth-v`:

```sh
sudo ./bin/shield -iface veth-v -mode generic
```

Driver mode is the default and may offer better performance, but it requires support from the interface driver:

```sh
sudo ./bin/shield -iface <interface> -mode driver
```

You can seed the blocklist when starting the program. A TTL of zero means the entry stays active until the process exits or you remove it:

```sh
sudo ./bin/shield \
  -iface <interface> \
  -mode generic \
  -static-block 192.0.2.10 \
  -ttl 5m
```

`-ttl` accepts Go duration syntax such as `30s`, `5m`, or `1h`. It applies to the initial `-static-block` entry.

### Interactive commands

While the program is running, enter commands in the same terminal:

```text
block 203.0.113.9 30s   # Block temporarily
block 203.0.113.9      # Block until removed or process exit
unblock 203.0.113.9    # Remove a block
quit                   # Detach and exit
```

Pressing Ctrl+C also stops the program and detaches XDP. Entries are held in an unpinned kernel map and disappear when the process exits.

The process prints aggregate statistics every second. Drop events are sampled, so they are not a log of every dropped packet.

## Command-line options

| Flag | Default | Meaning |
| --- | --- | --- |
| `-iface` | `veth-v` | Network interface to protect. |
| `-mode` | `driver` | XDP attachment mode: `driver` or `generic`. |
| `-static-block` | none | Optional IPv4 source address to block at startup. |
| `-ttl` | `0` | Initial block duration; `0` means permanent for this process. |

## Troubleshooting

- **Interface lookup failed:** check the name with `ip -br link` and pass it to `-iface`.
- **Driver mode is unsupported:** try `-mode generic`, which is more compatible but may be slower.
- **Permission or BPF load errors:** run the program with `sudo` and confirm that the running kernel supports the required BPF/XDP features.
- **Generation fails to find headers or tools:** install Clang/LLVM, GCC, Linux headers, and libbpf headers, then rerun `go generate ./cmd/shield`.

## Project layout

```text
bpf/shield.bpf.c          XDP program and kernel maps
cmd/shield/main.go        Go loader, CLI, and interactive controls
cmd/shield/gen.go         bpf2go generation directive
cmd/shield/shield_bpf*.go Generated Go bindings for the BPF object
```

## References

- [Cilium eBPF Go getting-started guide](https://github.com/cilium/ebpf/blob/main/docs/ebpf/guides/getting-started.md)
- [Linux BPF ring buffer documentation](https://docs.kernel.org/bpf/ringbuf.html)
