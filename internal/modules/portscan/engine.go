// Package portscan provides configurable, cancellable TCP scanning.
package portscan

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"sync"
	"time"
)

// Default engine tuning values. They keep scans responsive while avoiding the
// unbounded fan-out of the original 1000-goroutine implementation.
const (
	DefaultDialTimeout      = 500 * time.Millisecond
	DefaultHostDeadline     = 10 * time.Second
	DefaultMaxWorkers       = 100
	DefaultRatePerSecond    = 500
	legacyWorkerDialTimeout = 50 * time.Millisecond
)

// PortStatus classifies the outcome of a single TCP connection attempt.
type PortStatus string

const (
	// PortOpen means a TCP connection to the port was established.
	PortOpen PortStatus = "open"
	// PortClosed means the connection attempt failed.
	PortClosed PortStatus = "closed"
)

// Config configures a scan. The zero value is replaced by safe defaults via
// NormalizedConfig; callers typically set only the fields they want to tune.
type Config struct {
	// DialTimeout bounds each individual TCP connection attempt.
	DialTimeout time.Duration
	// MaxWorkers bounds the number of concurrent TCP connection attempts.
	MaxWorkers int
	// RateLimitPerSecond caps the number of connections initiated per second.
	// A value of zero disables rate limiting.
	RateLimitPerSecond int
	// Ports is the de-duplicated, sorted list of ports to probe. An empty
	// slice means every port from 1 through 65535.
	Ports []int
	// HostDeadline bounds the total time spent scanning a single host.
	HostDeadline time.Duration
}

// PortResult records the outcome of probing one port.
type PortResult struct {
	Port   int        `json:"port"`
	Status PortStatus `json:"status"`
	// Error holds the dial failure message for closed ports and is empty for
	// open ports. It never contains credentials or cluster-specific data.
	Error string `json:"error,omitempty"`
}

// HostResult is the structured result of scanning one host.
type HostResult struct {
	Host       string       `json:"host"`
	OpenPorts  []int        `json:"open_ports"`
	PortResult []PortResult `json:"port_results"`
	Error      string       `json:"error,omitempty"`
}

// NormalizedConfig fills zero-valued fields with safe defaults and validates
// the explicit values. The returned Ports slice is always populated and sorted.
func NormalizedConfig(config Config) (Config, error) {
	if config.DialTimeout <= 0 {
		config.DialTimeout = DefaultDialTimeout
	}
	if config.HostDeadline <= 0 {
		config.HostDeadline = DefaultHostDeadline
	}
	if config.MaxWorkers <= 0 {
		config.MaxWorkers = DefaultMaxWorkers
	}
	if config.RateLimitPerSecond < 0 {
		return Config{}, errors.New("rate limit must be zero or positive")
	}
	if len(config.Ports) == 0 {
		config.Ports = allPorts()
	} else {
		for _, port := range config.Ports {
			if port < minPort || port > maxPort {
				return Config{}, fmt.Errorf("port %d out of range (must be %d-%d)", port, minPort, maxPort)
			}
		}
	}
	return config, nil
}

// rateLimiter is a context-aware token bucket backed by a buffered channel.
// Tokens are replenished on a fixed tick so the average connection rate never
// exceeds RateLimitPerSecond; the burst capacity never exceeds MaxWorkers.
type rateLimiter struct {
	tokens chan struct{}
	done   chan struct{}
	wg     sync.WaitGroup
}

func newRateLimiter(ratePerSecond, maxWorkers int) *rateLimiter {
	if ratePerSecond <= 0 {
		return nil
	}
	burst := ratePerSecond
	if maxWorkers < burst {
		burst = maxWorkers
	}
	limiter := &rateLimiter{
		tokens: make(chan struct{}, burst),
		done:   make(chan struct{}),
	}
	for index := 0; index < burst; index++ {
		limiter.tokens <- struct{}{}
	}
	limiter.wg.Add(1)
	go func() {
		defer limiter.wg.Done()
		ticker := time.NewTicker(time.Second / time.Duration(ratePerSecond))
		defer ticker.Stop()
		for {
			select {
			case <-limiter.done:
				return
			case <-ticker.C:
				select {
				case limiter.tokens <- struct{}{}:
				case <-limiter.done:
					return
				default:
				}
			}
		}
	}()
	return limiter
}

// wait blocks until a token is available or the context is canceled.
func (limiter *rateLimiter) wait(ctx context.Context) error {
	if limiter == nil {
		return ctx.Err()
	}
	select {
	case <-limiter.tokens:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (limiter *rateLimiter) stop() {
	if limiter == nil {
		return
	}
	close(limiter.done)
	limiter.wg.Wait()
}

// dialProbe attempts one TCP connection and returns its structured result.
func dialProbe(ctx context.Context, dialer *net.Dialer, host string, port int) PortResult {
	result := PortResult{Port: port, Status: PortClosed}
	address := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	if err := conn.Close(); err != nil {
		result.Error = err.Error()
	}
	result.Status = PortOpen
	return result
}

// sortedOpenPorts returns the open ports from a port result list in order.
func sortedOpenPorts(results []PortResult) []int {
	openPorts := make([]int, 0, len(results))
	for _, result := range results {
		if result.Status == PortOpen {
			openPorts = append(openPorts, result.Port)
		}
	}
	sort.Ints(openPorts)
	return openPorts
}
