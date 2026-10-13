
package main

//go:generate sh -c "go tool bpf2go -type flow_event shield ../../bpf/shield.bpf.c -- -I/usr/include/$(gcc -dumpmachine)"
