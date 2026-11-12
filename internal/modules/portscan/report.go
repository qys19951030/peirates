package portscan

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// JSONReport renders a sweep report as stable, indented JSON. It contains only
// addresses, ports and dial errors: no credentials or cluster-specific values
// are ever written by the scanner.
func JSONReport(report Report) ([]byte, error) {
	payload, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal scan report: %w", err)
	}
	return append(payload, '\n'), nil
}

// TextReport renders a sweep report as the historical human-readable lines.
func TextReport(report Report) string {
	var builder bytes.Buffer
	for _, host := range report.Hosts {
		for _, port := range host.OpenPorts {
			fmt.Fprintf(&builder, "%s:%d open\n", host.Host, port)
		}
		if host.Error != "" {
			fmt.Fprintf(&builder, "%s error: %s\n", host.Host, host.Error)
		}
	}
	fmt.Fprintf(&builder,
		"hosts: %d total, %d with open ports, %d failed, %d open ports\n",
		report.TotalHosts, report.OpenHosts, report.FailedHosts, report.TotalOpenPorts)
	return builder.String()
}
