package portscan

import (
	"net"
	"testing"
)

func TestParseHostsIPv4(t *testing.T) {
	tests := []struct {
		name    string
		network string
		want    []string
	}{
		{
			name:    "slash 30 excludes network and broadcast",
			network: "192.0.2.0/30",
			want:    []string{"192.0.2.1", "192.0.2.2"},
		},
		{
			name:    "slash 31 keeps both point-to-point addresses",
			network: "192.0.2.0/31",
			want:    []string{"192.0.2.0", "192.0.2.1"},
		},
		{
			name:    "slash 32 returns the single host",
			network: "192.0.2.1/32",
			want:    []string{"192.0.2.1"},
		},
		{
			name:    "slash 24 excludes network and broadcast",
			network: "10.0.0.0/24",
			want:    []string{"10.0.0.1", "10.0.0.254"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := ParseHosts(test.network)
			if err != nil {
				t.Fatalf("ParseHosts returned error: %v", err)
			}
			if test.name == "slash 24 excludes network and broadcast" {
				if len(got) != 254 || got[0] != test.want[0] || got[253] != test.want[1] {
					t.Fatalf("hosts = %d entries, first %q last %q", len(got), got[0], got[len(got)-1])
				}
				return
			}
			if len(got) != len(test.want) {
				t.Fatalf("hosts = %#v, want %#v", got, test.want)
			}
			for index := range test.want {
				if got[index] != test.want[index] {
					t.Fatalf("hosts = %#v, want %#v", got, test.want)
				}
			}
		})
	}
}

func TestParseHostsOrderingAndUniqueness(t *testing.T) {
	hosts, err := ParseHosts("198.51.100.0/29")
	if err != nil {
		t.Fatal(err)
	}
	seen := make(map[string]bool, len(hosts))
	previous := ""
	for _, host := range hosts {
		if seen[host] {
			t.Fatalf("duplicate host %q", host)
		}
		seen[host] = true
		if previous != "" && host <= previous {
			t.Fatalf("hosts not ordered: %q followed %q", host, previous)
		}
		previous = host
		if net.ParseIP(host) == nil {
			t.Fatalf("host %q is not a valid IP", host)
		}
	}
}

func TestParseHostsIPv6(t *testing.T) {
	hosts, err := ParseHosts("2001:db8::/126")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"2001:db8::", "2001:db8::1", "2001:db8::2", "2001:db8::3"}
	if len(hosts) != len(want) {
		t.Fatalf("hosts = %#v, want %#v", hosts, want)
	}
	for index := range want {
		if hosts[index] != want[index] {
			t.Fatalf("hosts = %#v, want %#v", hosts, want)
		}
	}

	single, err := ParseHosts("2001:db8::1/128")
	if err != nil {
		t.Fatal(err)
	}
	if len(single) != 1 || single[0] != "2001:db8::1" {
		t.Fatalf("/128 hosts = %#v", single)
	}
}

func TestParseHostsErrors(t *testing.T) {
	tests := []string{
		"not-a-cidr",
		"192.0.2.0",
		"192.0.2.0/33",
		"2001:db8::/16",
		"2001:db8::/64",
		"10.0.0.0/8",
		"",
	}
	for _, network := range tests {
		t.Run(network, func(t *testing.T) {
			if hosts, err := ParseHosts(network); err == nil {
				t.Fatalf("ParseHosts(%q) = %#v, want error", network, hosts)
			}
		})
	}
}

func TestCIDRHostsPanicsOnInvalidInput(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("CIDRHosts did not panic on invalid input")
		}
	}()
	_ = CIDRHosts("not-a-cidr")
}

func TestCIDRHostsDelegatesToParseHosts(t *testing.T) {
	got := CIDRHosts("192.0.2.0/30")
	if len(got) != 2 || got[0] != "192.0.2.1" || got[1] != "192.0.2.2" {
		t.Fatalf("hosts = %#v", got)
	}
	if got := CIDRHosts("192.0.2.1/32"); len(got) != 1 || got[0] != "192.0.2.1" {
		t.Fatalf("/32 hosts = %#v", got)
	}
	if got := CIDRHosts("192.0.2.0/31"); len(got) != 2 {
		t.Fatalf("/31 hosts = %#v", got)
	}
}
