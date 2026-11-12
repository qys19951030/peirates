package portscan

import (
	"encoding/binary"
	"fmt"
	"math/big"
	"net"
)

// MaxEnumeratedHosts bounds how many addresses ParseHosts will return.
// Large IPv6 prefixes can encode astronomically many hosts, so enumeration is
// rejected instead of allocating an unbounded slice.
const MaxEnumeratedHosts = 1 << 16

// ParseHosts expands a CIDR network into its usable host addresses in
// ascending, deterministic order without duplicates.
//
// IPv4 networks exclude the network and broadcast addresses, except /31
// networks which follow RFC 3021 point-to-point semantics and /32 networks
// which contain a single host. IPv6 networks have no broadcast address, so
// every address in the prefix is returned. An error is returned when the
// input is not a valid CIDR or enumerating it would exceed MaxEnumeratedHosts.
func ParseHosts(network string) ([]string, error) {
	_, ipNet, err := net.ParseCIDR(network)
	if err != nil {
		return nil, fmt.Errorf("parse CIDR %q: %w", network, err)
	}
	ones, bits := ipNet.Mask.Size()
	if bits == 32 {
		return parseIPv4Hosts(ipNet, ones)
	}
	return parseIPv6Hosts(ipNet, ones, bits)
}

func parseIPv4Hosts(ipNet *net.IPNet, ones int) ([]string, error) {
	base := binary.BigEndian.Uint32(ipNet.IP.To4()) & binary.BigEndian.Uint32(ipNet.Mask)
	switch {
	case ones >= 32:
		return []string{uint32ToIPv4(base).String()}, nil
	case ones == 31:
		// RFC 3021: both addresses on a point-to-point link are usable.
		return []string{
			uint32ToIPv4(base).String(),
			uint32ToIPv4(base + 1).String(),
		}, nil
	default:
		usable := uint64(1)<<(32-ones) - 2
		if usable > MaxEnumeratedHosts {
			return nil, fmt.Errorf("network %q enumerates %d hosts, exceeding the limit of %d", ipNet.String(), usable, MaxEnumeratedHosts)
		}
		hosts := make([]string, 0, usable)
		for offset := uint64(1); offset <= usable; offset++ {
			hosts = append(hosts, uint32ToIPv4(base+uint32(offset)).String())
		}
		return hosts, nil
	}
}

func uint32ToIPv4(address uint32) net.IP {
	ip := make(net.IP, net.IPv4len)
	binary.BigEndian.PutUint32(ip, address)
	return ip
}

func parseIPv6Hosts(ipNet *net.IPNet, ones, bits int) ([]string, error) {
	total := new(big.Int).Lsh(big.NewInt(1), uint(bits-ones))
	if total.IsInt64() && total.Int64() > MaxEnumeratedHosts {
		return nil, fmt.Errorf("network %q enumerates %s hosts, exceeding the limit of %d", ipNet.String(), total.String(), MaxEnumeratedHosts)
	}
	if !total.IsInt64() {
		return nil, fmt.Errorf("network %q enumerates more than the limit of %d hosts", ipNet.String(), MaxEnumeratedHosts)
	}

	count := total.Int64()
	hosts := make([]string, 0, count)
	current := new(big.Int).SetBytes(ipNet.IP.To16())
	current.And(current, new(big.Int).SetBytes(ipNet.Mask))
	for index := int64(0); index < count; index++ {
		address := make(net.IP, net.IPv6len)
		current.FillBytes(address)
		hosts = append(hosts, address.String())
		current.Add(current, big.NewInt(1))
	}
	return hosts, nil
}

// CIDRHosts returns the usable host addresses in a CIDR network. It keeps the
// historical convention of panicking when the network cannot be parsed; host
// enumeration itself is delegated to ParseHosts, so /31 and /32 networks
// return their usable addresses instead of an empty slice.
func CIDRHosts(network string) []string {
	hosts, err := ParseHosts(network)
	if err != nil {
		panic(err)
	}
	return hosts
}
