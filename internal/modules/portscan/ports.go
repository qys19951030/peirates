package portscan

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

const (
	minPort = 1
	maxPort = 65535
)

// ParsePorts parses a comma-separated port specification such as
// "22,80,443,8000-8080" and returns a sorted, de-duplicated port list.
// Individual ports and both endpoints of an inclusive range must be within
// 1-65535, and ranges must not be reversed. An empty specification means the
// historical default of every port from 1 through 65535.
func ParsePorts(spec string) ([]int, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return allPorts(), nil
	}

	seen := make(map[int]struct{})
	var ports []int
	add := func(port int) error {
		if port < minPort || port > maxPort {
			return fmt.Errorf("port %d out of range (must be %d-%d)", port, minPort, maxPort)
		}
		if _, ok := seen[port]; ok {
			return nil
		}
		seen[port] = struct{}{}
		ports = append(ports, port)
		return nil
	}

	for _, field := range strings.Split(spec, ",") {
		field = strings.TrimSpace(field)
		if field == "" {
			return nil, fmt.Errorf("empty port field in specification %q", spec)
		}
		if !strings.Contains(field, "-") {
			port, err := strconv.Atoi(field)
			if err != nil {
				return nil, fmt.Errorf("invalid port %q in specification %q: %w", field, spec, err)
			}
			if err := add(port); err != nil {
				return nil, err
			}
			continue
		}

		endpoints := strings.Split(field, "-")
		if len(endpoints) != 2 {
			return nil, fmt.Errorf("invalid port range %q in specification %q", field, spec)
		}
		start, err := strconv.Atoi(strings.TrimSpace(endpoints[0]))
		if err != nil {
			return nil, fmt.Errorf("invalid range start %q in specification %q: %w", endpoints[0], spec, err)
		}
		end, err := strconv.Atoi(strings.TrimSpace(endpoints[1]))
		if err != nil {
			return nil, fmt.Errorf("invalid range end %q in specification %q: %w", endpoints[1], spec, err)
		}
		if start > end {
			return nil, fmt.Errorf("port range %d-%d is reversed", start, end)
		}
		for port := start; port <= end; port++ {
			if err := add(port); err != nil {
				return nil, err
			}
		}
	}

	sort.Ints(ports)
	return ports, nil
}

func allPorts() []int {
	ports := make([]int, maxPort)
	for index := range ports {
		ports[index] = index + 1
	}
	return ports
}
