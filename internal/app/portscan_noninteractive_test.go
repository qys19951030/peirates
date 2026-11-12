package app

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

func localListener(t *testing.T) (string, int, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	return "127.0.0.1", port, func() { _ = listener.Close() }
}

func TestNonInteractivePortScanFromModuleArgs(t *testing.T) {
	host, port, closeListener := localListener(t)
	defer closeListener()
	var output bytes.Buffer
	handled, err := runNonInteractivePortScan(
		[]string{"tcpscan", host, itoa(port), "4"},
		CommandLineOptions{}, &output)
	if err != nil {
		t.Fatalf("scan returned error: %v", err)
	}
	if !handled {
		t.Fatal("module-argument scan was not handled")
	}
	if !strings.Contains(output.String(), host+":"+itoa(port)+" open") {
		t.Fatalf("text report missing open port:\n%s", output.String())
	}
}

func TestNonInteractivePortScanEmitsJSON(t *testing.T) {
	host, port, closeListener := localListener(t)
	defer closeListener()
	var output bytes.Buffer
	handled, err := runNonInteractivePortScan(
		[]string{"tcpscan", "-target", host, "-ports", itoa(port), "-json"},
		CommandLineOptions{}, &output)
	if err != nil {
		t.Fatalf("scan returned error: %v", err)
	}
	if !handled {
		t.Fatal("flag-style scan was not handled")
	}
	var report map[string]interface{}
	if err := json.Unmarshal(output.Bytes(), &report); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, output.String())
	}
	if report["total_hosts"].(float64) != 1 || report["open_hosts"].(float64) != 1 {
		t.Fatalf("JSON summary = %+v", report)
	}
}

func TestNonInteractivePortScanUsesCommandLineOptions(t *testing.T) {
	host, port, closeListener := localListener(t)
	defer closeListener()
	opts := CommandLineOptions{
		portScanTarget:  host,
		portScanPorts:   itoa(port),
		portScanWorkers: 2,
		portScanJSON:    true,
	}
	var output bytes.Buffer
	handled, err := runNonInteractivePortScan(nil, opts, &output)
	if err != nil || !handled {
		t.Fatalf("handled = %v, err = %v", handled, err)
	}
	var report map[string]interface{}
	if err := json.Unmarshal(output.Bytes(), &report); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
}

func TestNonInteractivePortScanRejectsBadInput(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "invalid target", args: []string{"tcpscan", "not-a-cidr"}},
		{name: "invalid ports", args: []string{"tcpscan", "127.0.0.1", "99999"}},
		{name: "reversed range", args: []string{"tcpscan", "127.0.0.1", "8080-80"}},
		{name: "bad workers", args: []string{"tcpscan", "127.0.0.1", "22", "zero"}},
		{name: "missing target value", args: []string{"tcpscan", "-target"}},
		{name: "unknown flag", args: []string{"tcpscan", "-bogus"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var output bytes.Buffer
			handled, err := runNonInteractivePortScan(test.args, CommandLineOptions{}, &output)
			if err == nil {
				t.Fatalf("expected error, handled = %v output = %q", handled, output.String())
			}
		})
	}
}

func TestNonInteractivePortScanWithoutTargetFallsThrough(t *testing.T) {
	var output bytes.Buffer
	handled, err := runNonInteractivePortScan(nil, CommandLineOptions{}, &output)
	if err != nil || handled {
		t.Fatalf("handled = %v, err = %v", handled, err)
	}
}

func TestParseOptionsCapturesScanFlags(t *testing.T) {
	originalArgs := os.Args
	t.Cleanup(func() { os.Args = originalArgs })
	os.Args = []string{
		"peirates", "-c", "-m", "tcpscan",
		"-scan-target", "127.0.0.1", "-scan-ports", "22,80",
		"-scan-workers", "7", "-scan-json",
	}
	opts := CommandLineOptions{connectionConfig: &ServerInfo{}}
	parseOptions(&opts)
	if opts.portScanTarget != "127.0.0.1" || opts.portScanPorts != "22,80" || opts.portScanWorkers != 7 || !opts.portScanJSON {
		t.Fatalf("scan flags not captured: %#v", opts)
	}
}

func TestMainRunsPortScanFromFlags(t *testing.T) {
	host, port, closeListener := localListener(t)
	defer closeListener()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestMainSafeModuleHelper$")
	command.Env = append(os.Environ(),
		"PEIRATES_MAIN_MODULE_HELPER=1",
		"PEIRATES_TEST_MODULE=tcpscan",
		"PEIRATES_SCAN_TARGET="+host,
		"PEIRATES_SCAN_PORTS="+strconv.Itoa(port),
		"PEIRATES_SCAN_WORKERS=2",
		"PEIRATES_SCAN_JSON=1",
	)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("flag-driven scan failed: %v\n%s", err, output)
	}
	text := string(output)
	if !strings.Contains(text, "\"total_hosts\": 1") ||
		!strings.Contains(text, "\"open_ports\": [") ||
		!strings.Contains(text, strconv.Itoa(port)) {
		t.Fatalf("JSON report missing from Main output:\n%s", output)
	}
}

func itoa(value int) string {
	return strconv.Itoa(value)
}
