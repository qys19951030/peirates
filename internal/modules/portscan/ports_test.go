package portscan

import (
	"reflect"
	"testing"
)

func TestParsePorts(t *testing.T) {
	tests := []struct {
		name string
		spec string
		want []int
	}{
		{name: "empty defaults to all ports", spec: "", want: func() []int {
			ports := make([]int, maxPort)
			for index := range ports {
				ports[index] = index + 1
			}
			return ports
		}()},
		{name: "single port", spec: "22", want: []int{22}},
		{name: "comma list", spec: "22,80,443", want: []int{22, 80, 443}},
		{name: "inclusive range", spec: "8000-8004", want: []int{8000, 8001, 8002, 8003, 8004}},
		{name: "mixed spec", spec: "22,80,443,8000-8002", want: []int{22, 80, 443, 8000, 8001, 8002}},
		{name: "unsorted input is sorted", spec: "443,22,80", want: []int{22, 80, 443}},
		{name: "duplicates are removed", spec: "22,22,80,80", want: []int{22, 80}},
		{name: "overlapping ranges merge", spec: "8000-8002,8001-8003", want: []int{8000, 8001, 8002, 8003}},
		{name: "whitespace tolerated", spec: " 22 , 80 ", want: []int{22, 80}},
		{name: "single port range", spec: "65535-65535", want: []int{65535}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := ParsePorts(test.spec)
			if err != nil {
				t.Fatalf("ParsePorts returned error: %v", err)
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("ParsePorts(%q) = %#v, want %#v", test.spec, got, test.want)
			}
		})
	}
}

func TestParsePortsErrors(t *testing.T) {
	tests := []string{
		"0",
		"65536",
		"-1",
		"22,",
		",22",
		"22,,80",
		"8080-80",
		"1-65536",
		"0-10",
		"abc",
		"22,abc",
		"22-abc",
		"1-2-3",
	}
	for _, spec := range tests {
		t.Run(spec, func(t *testing.T) {
			if ports, err := ParsePorts(spec); err == nil {
				t.Fatalf("ParsePorts(%q) = %#v, want error", spec, ports)
			}
		})
	}
}
