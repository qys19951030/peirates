package app

import "strings"

// moduleArgs holds the raw arguments attached to the -m module invocation.
// It is set during startup and read by modules that support non-interactive
// parameters, such as tcpscan.
var moduleArgs string

// portScanFlagOptions is populated from command-line flags at startup.
var portScanFlagOptions CommandLineOptions

func scanModuleArgs() string {
	return moduleArgs
}

func currentPortScanOptions() CommandLineOptions {
	return portScanFlagOptions
}

func splitModuleFields(raw string) []string {
	fields := strings.Fields(raw)
	if len(fields) == 0 {
		return nil
	}
	return fields
}
