package app

import (
	"context"
	"io"
	"time"

	"github.com/inguardians/peirates/internal/modules/portscan"
)

func scanWorker(ip string, ports, results chan int)   { portscan.ScanWorker(ip, ports, results) }
func scanController(ip string)                        { portscan.Scan(ip) }
func cidrHosts(network string) []string               { return portscan.CIDRHosts(network) }
func parseCIDRHosts(network string) ([]string, error) { return portscan.ParseHosts(network) }
func test()                                           { println("Test") }

// portScanOptions carries the non-interactive scan parameters collected from
// command-line flags or tcpscan module arguments.
type portScanOptions struct {
	target  string
	ports   string
	workers int
	json    bool
}

// runPortScan performs a non-interactive scan against an IP address or CIDR
// and writes either a JSON or human-readable report to output. It returns the
// scan error, if any, so callers control process behavior.
func runPortScan(ctx context.Context, options portScanOptions, output outputSink) error {
	ports, err := portscan.ParsePorts(options.ports)
	if err != nil {
		return err
	}
	config := portscan.DefaultConfig()
	config.Ports = ports
	if options.workers > 0 {
		config.MaxWorkers = options.workers
	}
	if config.HostDeadline > 30*time.Second {
		config.HostDeadline = 30 * time.Second
	}
	report, err := portscan.Sweep(ctx, []string{options.target}, config)
	if options.json {
		payload, marshalErr := portscan.JSONReport(report)
		if marshalErr != nil {
			return marshalErr
		}
		_, _ = output.Write(payload)
	} else {
		_, _ = io.WriteString(output, portscan.TextReport(report))
	}
	return err
}
