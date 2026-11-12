package portscan

import (
	"context"
	"runtime"
	"testing"
	"time"
)

func TestCanceledSweepDoesNotLeakGoroutines(t *testing.T) {
	host, openPort, closeListener := listenOnRandomPort(t)
	defer closeListener()

	baseline := runtime.NumGoroutine()
	for iteration := 0; iteration < 5; iteration++ {
		ctx, cancel := context.WithCancel(context.Background())
		finished := make(chan struct{})
		go func() {
			_, _ = Sweep(ctx, []string{host}, Config{
				DialTimeout:        time.Second,
				HostDeadline:       time.Minute,
				MaxWorkers:         8,
				RateLimitPerSecond: 10,
				Ports:              []int{openPort},
			})
			close(finished)
		}()
		time.Sleep(20 * time.Millisecond)
		cancel()
		<-finished
	}
	// Give the runtime time to reap exited goroutines before counting.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && runtime.NumGoroutine() > baseline+2 {
		runtime.Gosched()
		time.Sleep(25 * time.Millisecond)
	}
	if leaked := runtime.NumGoroutine() - baseline; leaked > 2 {
		t.Fatalf("goroutine count grew by %d after canceled sweeps", leaked)
	}
}
