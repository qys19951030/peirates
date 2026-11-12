package portscan

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestSweepAggregatesMultipleHostsAndDeduplicates(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	openPort := listener.Addr().(*net.TCPAddr).Port
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	// The single-host CIDR and the bare IP resolve to the same target.
	report, err := Sweep(context.Background(), []string{"127.0.0.1/32", "127.0.0.1"}, Config{
		DialTimeout:        100 * time.Millisecond,
		HostDeadline:       5 * time.Second,
		MaxWorkers:         4,
		RateLimitPerSecond: 0,
		Ports:              []int{openPort},
	})
	if err != nil {
		t.Fatalf("Sweep returned error: %v", err)
	}
	if report.TotalHosts != 1 || len(report.Hosts) != 1 {
		t.Fatalf("report = %+v, want one de-duplicated host", report)
	}
	if report.ScannedHosts != 1 || report.OpenHosts != 1 || report.TotalOpenPorts != 1 || report.FailedHosts != 0 {
		t.Fatalf("summary counts = %+v", report)
	}
	if report.Hosts[0].Host != "127.0.0.1" || len(report.Hosts[0].OpenPorts) != 1 {
		t.Fatalf("host result = %+v", report.Hosts[0])
	}
}

func TestSweepContinuesAfterHostFailure(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	openPort := listener.Addr().(*net.TCPAddr).Port
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	// 127.0.0.2 is not assigned on the loopback interface in this environment,
	// so its probes time out while 127.0.0.1 still completes successfully.
	report, err := Sweep(context.Background(), []string{"127.0.0.1", "127.0.0.2"}, Config{
		DialTimeout:        50 * time.Millisecond,
		HostDeadline:       500 * time.Millisecond,
		MaxWorkers:         2,
		RateLimitPerSecond: 0,
		Ports:              []int{openPort},
	})
	if err != nil {
		t.Fatalf("Sweep returned error: %v", err)
	}
	if report.TotalHosts != 2 || report.ScannedHosts != 2 || report.OpenHosts != 1 {
		t.Fatalf("report = %+v", report)
	}
	byHost := map[string]HostResult{}
	for _, host := range report.Hosts {
		byHost[host.Host] = host
	}
	if len(byHost["127.0.0.1"].OpenPorts) != 1 {
		t.Fatalf("reachable host result = %+v", byHost["127.0.0.1"])
	}
	failed := byHost["127.0.0.2"]
	if len(failed.PortResult) != 1 || failed.PortResult[0].Status != PortClosed {
		t.Fatalf("unreachable host result = %+v", failed)
	}
}

func TestSweepReturnsErrorForInvalidTarget(t *testing.T) {
	if _, err := Sweep(context.Background(), []string{"not-a-cidr"}, DefaultConfig()); err == nil {
		t.Fatal("Sweep accepted an invalid target")
	}
}

func TestSweepScansIPv6Loopback(t *testing.T) {
	listener, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	defer listener.Close()
	openPort := listener.Addr().(*net.TCPAddr).Port
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	report, err := Sweep(context.Background(), []string{"::1/128"}, Config{
		DialTimeout:        100 * time.Millisecond,
		HostDeadline:       5 * time.Second,
		MaxWorkers:         2,
		RateLimitPerSecond: 0,
		Ports:              []int{openPort},
	})
	if err != nil {
		t.Fatalf("IPv6 sweep returned error: %v", err)
	}
	if report.TotalHosts != 1 || report.Hosts[0].Host != "::1" {
		t.Fatalf("IPv6 report = %+v", report)
	}
	if len(report.Hosts[0].OpenPorts) != 1 || report.Hosts[0].OpenPorts[0] != openPort {
		t.Fatalf("IPv6 open ports = %#v", report.Hosts[0].OpenPorts)
	}
}

func TestSweepStopsOnCancellation(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	finished := make(chan struct{})
	go func() {
		_, _ = Sweep(ctx, []string{"127.0.0.1/30"}, Config{
			DialTimeout:        time.Second,
			HostDeadline:       time.Minute,
			MaxWorkers:         2,
			RateLimitPerSecond: 1,
			Ports:              allPorts(),
		})
		close(finished)
	}()
	time.Sleep(150 * time.Millisecond)
	cancel()
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("Sweep did not return after context cancellation")
	}
}
