package portscan

import (
	"context"
	"errors"
)

// ScanHost probes the configured ports on one host and returns a structured
// result. The returned error covers configuration and input problems;
// per-port dial failures and context cancellation are recorded on the
// HostResult instead. It is a single-target wrapper around the shared sweep
// engine so host and network scans use the same concurrency and rate limits.
func ScanHost(ctx context.Context, host string, config Config) (HostResult, error) {
	if host == "" {
		return HostResult{}, errors.New("host must not be empty")
	}
	report, err := Sweep(ctx, []string{host}, config)
	if len(report.Hosts) == 0 {
		return HostResult{Host: host}, err
	}
	return report.Hosts[0], err
}
