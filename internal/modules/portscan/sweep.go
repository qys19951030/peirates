package portscan

import (
	"context"
	"net"
	"sort"
	"sync"
)

// Report aggregates the host results from a network sweep.
type Report struct {
	Targets        []string     `json:"targets"`
	Hosts          []HostResult `json:"hosts"`
	TotalHosts     int          `json:"total_hosts"`
	ScannedHosts   int          `json:"scanned_hosts"`
	OpenHosts      int          `json:"open_hosts"`
	FailedHosts    int          `json:"failed_hosts"`
	TotalOpenPorts int          `json:"total_open_ports"`
}

type probeJob struct {
	hostIndex int
	host      string
	port      int
}

// expandTargets accepts individual IP addresses and CIDR networks and returns
// a sorted, de-duplicated list of host addresses.
func expandTargets(targets []string) ([]string, error) {
	seen := make(map[string]struct{})
	var hosts []string
	for _, target := range targets {
		if ip := net.ParseIP(target); ip != nil {
			hostAddress := ip.String()
			if _, ok := seen[hostAddress]; ok {
				continue
			}
			seen[hostAddress] = struct{}{}
			hosts = append(hosts, hostAddress)
			continue
		}
		cidrHosts, err := ParseHosts(target)
		if err != nil {
			return nil, err
		}
		for _, host := range cidrHosts {
			if _, ok := seen[host]; ok {
				continue
			}
			seen[host] = struct{}{}
			hosts = append(hosts, host)
		}
	}
	sort.Strings(hosts)
	return hosts, nil
}

// Sweep expands the CIDR targets and scans every unique host using one shared
// worker pool and rate-limit budget. A single host failing or being
// unreachable does not stop the sweep; the failure is recorded on that host's
// result. Canceling the context terminates the whole sweep, including probes
// already in flight. The returned Report is always populated; a non-nil error
// indicates the sweep was interrupted (for example by context cancellation).
func Sweep(ctx context.Context, targets []string, config Config) (Report, error) {
	normalized, err := NormalizedConfig(config)
	if err != nil {
		return Report{}, err
	}
	hosts, err := expandTargets(targets)
	if err != nil {
		return Report{}, err
	}
	report := Report{Targets: hosts, TotalHosts: len(hosts)}
	if len(hosts) == 0 {
		return report, nil
	}

	hostCtxs := make([]context.Context, len(hosts))
	cancels := make([]context.CancelFunc, len(hosts))
	for index := range hosts {
		hostCtxs[index], cancels[index] = context.WithTimeout(ctx, normalized.HostDeadline)
	}
	defer func() {
		for _, cancel := range cancels {
			cancel()
		}
	}()

	limiter := newRateLimiter(normalized.RateLimitPerSecond, normalized.MaxWorkers)
	defer limiter.stop()
	dialer := &net.Dialer{Timeout: normalized.DialTimeout}
	jobs := make(chan probeJob)
	portResults := make([][]PortResult, len(hosts))
	var resultMu sync.Mutex
	var workers sync.WaitGroup

	for index := 0; index < normalized.MaxWorkers; index++ {
		workers.Add(1)
		go runProbeWorker(ctx, hostCtxs, jobs, dialer, limiter, portResults, &resultMu, &workers)
	}

	feedErr := feedProbeJobs(ctx, hosts, normalized.Ports, jobs)
	close(jobs)
	workers.Wait()
	report.assemble(hosts, portResults, ctx)
	return report, feedErr
}

func runProbeWorker(
	sweepCtx context.Context,
	hostCtxs []context.Context,
	jobs <-chan probeJob,
	dialer *net.Dialer,
	limiter *rateLimiter,
	portResults [][]PortResult,
	resultMu *sync.Mutex,
	waitGroup *sync.WaitGroup,
) {
	defer waitGroup.Done()
	for {
		select {
		case <-sweepCtx.Done():
			return
		case job, ok := <-jobs:
			if !ok {
				return
			}
			hostCtx := hostCtxs[job.hostIndex]
			if err := limiter.wait(hostCtx); err != nil {
				resultMu.Lock()
				portResults[job.hostIndex] = append(portResults[job.hostIndex], PortResult{
					Port: job.port, Status: PortClosed, Error: err.Error(),
				})
				resultMu.Unlock()
				continue
			}
			result := probeHook(hostCtx, dialer, job.host, job.port)
			resultMu.Lock()
			portResults[job.hostIndex] = append(portResults[job.hostIndex], result)
			resultMu.Unlock()
		}
	}
}

func feedProbeJobs(ctx context.Context, hosts []string, ports []int, jobs chan<- probeJob) error {
	for hostIndex, host := range hosts {
		for _, port := range ports {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case jobs <- probeJob{hostIndex: hostIndex, host: host, port: port}:
			}
		}
	}
	return nil
}

func (report *Report) assemble(hosts []string, portResults [][]PortResult, sweepCtx context.Context) {
	report.Hosts = make([]HostResult, 0, len(hosts))
	for index, hostAddress := range hosts {
		results := append([]PortResult(nil), portResults[index]...)
		sort.Slice(results, func(left, right int) bool {
			return results[left].Port < results[right].Port
		})
		hostResult := HostResult{
			Host:       hostAddress,
			PortResult: results,
			OpenPorts:  sortedOpenPorts(results),
		}
		if len(results) > 0 {
			report.ScannedHosts++
		}
		if len(hostResult.OpenPorts) > 0 {
			report.OpenHosts++
			report.TotalOpenPorts += len(hostResult.OpenPorts)
		}
		if sweepCtx.Err() != nil {
			hostResult.Error = sweepCtx.Err().Error()
		}
		if len(results) == 0 || hostResult.Error != "" {
			report.FailedHosts++
		}
		report.Hosts = append(report.Hosts, hostResult)
	}
}
