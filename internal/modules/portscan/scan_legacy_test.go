package portscan

import (
	"context"
	"testing"
	"time"
)

func TestDefaultConfigPortsAndLimits(t *testing.T) {
	config, err := NormalizedConfig(Config{})
	if err != nil {
		t.Fatal(err)
	}
	if len(config.Ports) != maxPort || config.Ports[0] != minPort || config.Ports[maxPort-1] != maxPort {
		t.Fatalf("default ports = %d entries, want %d", len(config.Ports), maxPort)
	}
	if config.MaxWorkers <= 0 || config.DialTimeout <= 0 || config.HostDeadline <= 0 {
		t.Fatalf("default config has non-positive tuning: %+v", config)
	}
	if _, err := NormalizedConfig(Config{MaxWorkers: 1, Ports: []int{0}}); err == nil {
		t.Fatal("invalid port was accepted")
	}
}

func TestScanHostEmptyHostRejected(t *testing.T) {
	if _, err := ScanHost(context.Background(), "", DefaultConfig()); err == nil {
		t.Fatal("empty host was accepted")
	}
}

func TestSweepEmptyTargets(t *testing.T) {
	report, err := Sweep(context.Background(), nil, Config{
		DialTimeout:  100 * time.Millisecond,
		HostDeadline: time.Second,
		MaxWorkers:   2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.TotalHosts != 0 || len(report.Hosts) != 0 {
		t.Fatalf("empty sweep report = %+v", report)
	}
}
