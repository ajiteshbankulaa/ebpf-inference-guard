module example.com/ebpf-shield

go 1.27.2

require (
	github.com/cilium/ebpf v0.22.0
	golang.org/x/sys v0.43.0
)

tool github.com/cilium/ebpf/cmd/bpf2go
