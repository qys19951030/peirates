package portscan

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// TestSweepConcurrencyDoesNotExceedWorkers drives real TCP dials through a
// listener and asserts the worker pool never has more than MaxWorkers probes
// in flight at once.
func TestSweepConcurrencyDoesNotExceedWorkers(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			time.Sleep(20 * time.Millisecond)
			_ = conn.Close()
		}
	}()

	const maxWorkers = 3
	var inFlight, peak int32
	originalProbe := probeHook
	probeHook = instrumentedProbe(&inFlight, &peak, maxWorkers, originalProbe)
	t.Cleanup(func() { probeHook = originalProbe })

	_, err = Sweep(context.Background(), []string{"127.0.0.1"}, Config{
		DialTimeout:        time.Second,
		HostDeadline:       30 * time.Second,
		MaxWorkers:         maxWorkers,
		RateLimitPerSecond: 0,
		Ports:              repeatPort(port, 30),
	})
	if err != nil {
		t.Fatalf("Sweep returned error: %v", err)
	}
	if peak > maxWorkers {
		t.Fatalf("peak in-flight probes = %d, exceeds MaxWorkers %d", peak, maxWorkers)
	}
	if peak == 0 {
		t.Fatal("no probes were observed")
	}
}

func repeatPort(port, count int) []int {
	ports := make([]int, count)
	for index := range ports {
		ports[index] = port
	}
	return ports
}

func instrumentedProbe(inFlight, peak *int32, maxWorkers int32, next func(context.Context, *net.Dialer, string, int) PortResult) func(context.Context, *net.Dialer, string, int) PortResult {
	return func(ctx context.Context, dialer *net.Dialer, host string, port int) PortResult {
		current := atomic.AddInt32(inFlight, 1)
		for {
			recorded := atomic.LoadInt32(peak)
			if current <= recorded || atomic.CompareAndSwapInt32(peak, recorded, current) {
				break
			}
		}
		defer atomic.AddInt32(inFlight, -1)
		return next(ctx, dialer, host, port)
	}
}
