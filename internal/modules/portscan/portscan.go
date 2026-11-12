package portscan

import (
	"context"
	"fmt"
	"net"
	"strconv"
)

// ScanWorker tests queued TCP ports for a host and sends each open port on
// results. A failed connection sends zero so callers can count every probe.
// It is retained as the low-level probing primitive used by existing callers.
func ScanWorker(ip string, ports, results chan int) {
	dialer := &net.Dialer{Timeout: legacyWorkerDialTimeout}
	for port := range ports {
		address := net.JoinHostPort(ip, strconv.Itoa(port))
		conn, err := dialer.Dial("tcp", address)
		if err != nil {
			results <- 0
			continue
		}
		if err := conn.Close(); err != nil {
			results <- 0
			continue
		}
		results <- port
	}
}

// Scan tests TCP ports on an IP address and prints the open ones in the
// historical "ip:port open" human-readable form. Scanning runs through the
// configurable, rate-limited engine rather than a separate implementation.
func Scan(ip string) {
	result, err := ScanHost(context.Background(), ip, DefaultConfig())
	if err != nil {
		fmt.Printf("scan of %s failed: %v\n", ip, err)
		return
	}
	if result.Error != "" {
		fmt.Printf("scan of %s stopped: %s\n", ip, result.Error)
	}
	for _, port := range result.OpenPorts {
		fmt.Printf("%s:%d open\n", ip, port)
	}
}

// DefaultConfig returns the safe engine defaults used by Scan.
func DefaultConfig() Config {
	return Config{
		DialTimeout:        DefaultDialTimeout,
		HostDeadline:       DefaultHostDeadline,
		MaxWorkers:         DefaultMaxWorkers,
		RateLimitPerSecond: DefaultRatePerSecond,
		Ports:              allPorts(),
	}
}
