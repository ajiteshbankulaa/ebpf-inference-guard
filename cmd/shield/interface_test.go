package main

import (
	"os"
	"strings"
	"testing"
)

func TestParseDefaultRoute(t *testing.T) {
	const routes = "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n" +
		"eth1 00000000 0100000A 0003 0 0 200 00000000 0 0 0\n" +
		"eth0 00000000 0100000A 0003 0 0 50 00000000 0 0 0\n" +
		"eth2 00000001 00000000 0001 0 0 1 00000000 0 0 0\n"
	got, err := parseDefaultRouteName(strings.NewReader(routes))
	if err != nil {
		t.Fatal(err)
	}
	if got != "eth0" {
		t.Fatalf("got %q, want eth0", got)
	}
}

func TestParseDefaultRouteRejectsMissingRoute(t *testing.T) {
	_, err := parseDefaultRouteName(strings.NewReader("Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n"))
	if err == nil {
		t.Fatal("expected missing default route error")
	}
}

func TestDefaultRouteInterfaceMatchesProcTable(t *testing.T) {
	content, err := os.ReadFile("/proc/net/route")
	if err != nil {
		t.Fatal(err)
	}
	name, err := parseDefaultRouteName(strings.NewReader(string(content)))
	if err != nil {
		t.Skipf("environment has no IPv4 default route: %v", err)
	}
	iface, err := defaultRouteInterface()
	if err != nil {
		t.Fatal(err)
	}
	if iface.Name != name {
		t.Fatalf("got %q, want %q", iface.Name, name)
	}
}
