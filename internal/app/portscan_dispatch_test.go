package app

import (
	"bytes"
	"io"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/inguardians/peirates/internal/modules"
)

func TestRunModuleCommandDispatchesTCPScanWithArgs(t *testing.T) {
	host, port, closeListener := localListener(t)
	defer closeListener()

	previousStdout := os.Stdout
	readEnd, writeEnd, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = writeEnd
	defer func() { os.Stdout = previousStdout }()

	var output bytes.Buffer
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(&output, readEnd)
		close(done)
	}()

	result, found := runModuleCommand(
		newModuleRegistry(NewSession(ServerInfo{})),
		NewSession(ServerInfo{}),
		"tcpscan "+host+" "+strconv.Itoa(port)+" 2 json")
	_ = writeEnd.Close()
	<-done

	if result != modules.Continue || !found {
		t.Fatalf("result = %v, found = %v, want Continue/true", result, found)
	}
	if !strings.Contains(output.String(), "\"total_hosts\": 1") {
		t.Fatalf("dispatch did not emit JSON report:\n%s", output.String())
	}
}
