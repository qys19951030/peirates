# Scan TCP ports

## Menu entry

- **Menu item:** 93
- **Canonical command:** `tcpscan`
- **Aliases:** `portscan`, `tcp scan`, `port scan`
- **Maturity:** Supported; CIDR mode is explicitly described as hidden and potentially slow

## Purpose

Attempt TCP connections to one or more targets. By default every port from 1 through 65535 is probed, but a specific port specification can be supplied. Targets may be individual IPv4/IPv6 addresses or CIDR networks, which are expanded into their usable hosts before scanning.

## Prerequisites and authorization

The Peirates process needs network reachability to the targets. Port scanning can trigger monitoring or affect fragile services; scan only approved address ranges.

## Usage

```text
tcpscan
```

The interactive command prompts for an IPv4 address or CIDR. Unattended one-shot scans are supported either through module arguments:

```text
peirates -m "tcpscan 10.0.0.1 22,80,443,8000-8080 16 json"
peirates -m "tcpscan -target 10.0.0.0/30 -ports 443 -workers 8 -json"
```

or through dedicated command-line flags:

```text
peirates -c -m tcpscan -scan-target 10.0.0.1 -scan-ports 22,80,443 -scan-workers 16 -scan-json
```

- `-scan-target`: an IPv4/IPv6 address or CIDR network.
- `-scan-ports`: a port specification such as `22,80,443,8000-8080`; empty means all ports.
- `-scan-workers`: maximum concurrent TCP connection attempts.
- `-scan-json`: emit a machine-readable JSON report instead of the text summary.

## What it does

The scan runs on a context-aware engine with a bounded worker pool and a token-bucket rate limiter, both configurable through `portscan.Config`. All hosts in a sweep share one concurrency and rate budget, and a single host failing does not interrupt the remaining hosts.

CIDR expansion is handled by `ParseHosts`: IPv4 networks exclude the network and broadcast addresses, `/31` networks follow RFC 3021 and return both point-to-point addresses, `/32` returns the single address, and IPv6 prefixes enumerate every address. Prefixes that would enumerate more than 65536 hosts are rejected instead of being allocated. The legacy `CIDRHosts` wrapper retains its panic-on-unparseable-input convention but delegates enumeration to `ParseHosts`.

## Expected output

In text mode, open ports are printed in ascending order as `IP:PORT open`, followed by a summary of total, open and failed hosts and the total number of open ports. In JSON mode the report contains stable fields (`targets`, `hosts`, `total_hosts`, `scanned_hosts`, `open_hosts`, `failed_hosts`, `total_open_ports`); each host records its open ports, per-port statuses and any dial error. The report never contains credentials or cluster-specific values.

## Side effects and cleanup

The scan creates a large number of outbound connections but does not intentionally modify targets. No cleanup is normally required.

## Failure modes

Invalid CIDR input and oversized prefixes return a descriptive error instead of panicking. Interactive CIDR mode reports parse errors and returns to the caller rather than exiting. Invalid port specifications (out-of-range ports, reversed ranges, empty fields, non-numeric values) are rejected before any connection is made. Per-host dial failures and timeouts are recorded on that host's result and do not stop a sweep. Firewalls and the dial timeout can still make open ports appear closed.

## Implementation and tests

The reusable engine lives in the [`portscan`](../../internal/modules/portscan) package: `cidr.go` for host expansion, `ports.go` for port specifications, `engine.go` for configuration and rate limiting, `scanner.go` for `ScanHost`, `sweep.go` for network sweeps and `report.go` for JSON/text rendering. Application wiring lives in [`menu_tcp_portscan.go`](../../internal/app/menu_tcp_portscan.go), [`portscan.go`](../../internal/app/portscan.go) and [`portscan_noninteractive.go`](../../internal/app/portscan_noninteractive.go). Tests use loopback listeners and cover CIDR boundaries, IPv6, port validation, structured results, JSON reports, cancellation, rate limiting and concurrency bounds.
