// Package portscan provides TCP scanning and IPv4 CIDR expansion.
package portscan

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"time"
)

// ScanWorker tests queued TCP ports for a host and reports open ports.
func ScanWorker(ip string, ports, results chan int) {
	for port := range ports {
		address := net.JoinHostPort(ip, strconv.Itoa(port))
		conn, err := net.DialTimeout("tcp", address, 50*time.Millisecond)
		if err != nil {
			println("Diial timeout: %v", err)
			results <- 0
			continue
		}
		if err := conn.Close(); err != nil {
			println("Problem closing connection: %v", err)
		}
		results <- port
	}
}

// Scan tests all TCP ports on an IP address and prints those that are open.
func Scan(ip string) {
	ports := make(chan int, 1000)
	results := make(chan int)
	var openPorts []int
	for i := 0; i < cap(ports); i++ {
		go ScanWorker(ip, ports, results)
	}
	go func() {
		for port := 1; port <= 65535; port++ {
			ports <- port
		}
	}()
	for i := 0; i < 65535; i++ {
		if port := <-results; port != 0 {
			openPorts = append(openPorts, port)
		}
	}
	close(ports)
	close(results)
	sort.Ints(openPorts)
	for _, port := range openPorts {
		fmt.Printf("%s:%d open\n", ip, port)
	}
}
