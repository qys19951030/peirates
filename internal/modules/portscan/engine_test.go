package portscan

import (
	"context"
	"encoding/json"
	"net"
	"testing"
	"time"
)

func listenOnRandomPort(t *testing.T) (string, int, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	return "127.0.0.1", port, func() { _ = listener.Close() }
}

func TestScanHostReportsOpenAndClosedPorts(t *testing.T) {
	host, openPort, closeListener := listenOnRandomPort(t)
	defer closeListener()
	closedListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedPort := closedListener.Addr().(*net.TCPAddr).Port
	_ = closedListener.Close()

	result, err := ScanHost(context.Background(), host, Config{
		DialTimeout:        100 * time.Millisecond,
		HostDeadline:       5 * time.Second,
		MaxWorkers:         4,
		RateLimitPerSecond: 0,
		Ports:              []int{closedPort, openPort},
	})
	if err != nil {
		t.Fatalf("ScanHost returned error: %v", err)
	}
	if result.Host != host {
		t.Fatalf("host = %q, want %q", result.Host, host)
	}
	if len(result.OpenPorts) != 1 || result.OpenPorts[0] != openPort {
		t.Fatalf("open ports = %#v, want [%d]", result.OpenPorts, openPort)
	}
	statuses := map[int]PortStatus{}
	for _, portResult := range result.PortResult {
		statuses[portResult.Port] = portResult.Status
		if portResult.Status == PortClosed && portResult.Error == "" {
			t.Fatalf("closed port %d has no error message", portResult.Port)
		}
	}
	if statuses[openPort] != PortOpen {
		t.Fatalf("open port status = %q", statuses[openPort])
	}
	if statuses[closedPort] != PortClosed {
		t.Fatalf("closed port status = %q", statuses[closedPort])
	}
}

func TestJSONReportRoundTrip(t *testing.T) {
	host, openPort, closeListener := listenOnRandomPort(t)
	defer closeListener()
	report, err := Sweep(context.Background(), []string{host}, Config{
		DialTimeout:        100 * time.Millisecond,
		HostDeadline:       5 * time.Second,
		MaxWorkers:         2,
		RateLimitPerSecond: 0,
		Ports:              []int{openPort},
	})
	if err != nil {
		t.Fatalf("Sweep returned error: %v", err)
	}
	payload, err := JSONReport(report)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Report
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatalf("JSON report is not valid: %v\n%s", err, payload)
	}
	if decoded.TotalHosts != 1 || decoded.OpenHosts != 1 || decoded.TotalOpenPorts != 1 {
		t.Fatalf("decoded summary = %+v", decoded)
	}
	if len(decoded.Hosts) != 1 || decoded.Hosts[0].Host != host || len(decoded.Hosts[0].OpenPorts) != 1 || decoded.Hosts[0].OpenPorts[0] != openPort {
		t.Fatalf("decoded hosts = %+v", decoded.Hosts)
	}
}

func TestScanHostRespondsToCancellation(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	acceptDone := make(chan struct{})
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				close(acceptDone)
				return
			}
			_ = conn.Close()
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	finished := make(chan struct{})
	var result HostResult
	go func() {
		result, _ = ScanHost(ctx, "127.0.0.1", Config{
			DialTimeout:        time.Second,
			HostDeadline:       time.Minute,
			MaxWorkers:         8,
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
		t.Fatal("ScanHost did not return after context cancellation")
	}
	if result.Error == "" {
		t.Fatal("canceled scan did not record an error")
	}
}

func TestSweepRespectsWorkerAndRateLimits(t *testing.T) {
	const maxWorkers, rateLimit = 4, 20
	limiter := newRateLimiter(rateLimit, maxWorkers)
	defer limiter.stop()

	start := time.Now()
	ctx := context.Background()
	for index := 0; index < rateLimit+5; index++ {
		if err := limiter.wait(ctx); err != nil {
			t.Fatalf("limiter wait failed: %v", err)
		}
	}
	elapsed := time.Since(start)
	// Burst capacity is capped at the worker count; the remaining five tokens
	// arrive one per rate interval, so the floor is five intervals.
	minimum := 5 * time.Second / time.Duration(rateLimit)
	if elapsed < minimum {
		t.Fatalf("rate limiter issued %d tokens in %v, faster than %v floor", rateLimit+5, elapsed, minimum)
	}

	// Canceling wait must return promptly instead of blocking for a token.
	cancelCtx, cancel := context.WithCancel(context.Background())
	slowLimiter := newRateLimiter(1, 1)
	defer slowLimiter.stop()
	if err := slowLimiter.wait(cancelCtx); err != nil {
		t.Fatalf("initial token failed: %v", err)
	}
	cancel()
	done := make(chan error, 1)
	go func() { done <- slowLimiter.wait(cancelCtx) }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled limiter wait returned nil error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("limiter wait did not return after cancellation")
	}
}
