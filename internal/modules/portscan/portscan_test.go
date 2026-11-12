package portscan

import (
	"net"
	"testing"
)

func TestScanWorkerReportsOpenAndClosedPorts(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	openPort := listener.Addr().(*net.TCPAddr).Port
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedPort := closed.Addr().(*net.TCPAddr).Port
	_ = closed.Close()
	ports, results := make(chan int, 2), make(chan int, 2)
	ports <- openPort
	ports <- closedPort
	close(ports)
	go ScanWorker("127.0.0.1", ports, results)
	first, second := <-results, <-results
	if !((first == openPort && second == 0) || (first == 0 && second == openPort)) {
		t.Fatalf("results = %d, %d", first, second)
	}
}
