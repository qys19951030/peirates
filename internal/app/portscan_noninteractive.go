package app

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"

	"github.com/inguardians/peirates/internal/modules/portscan"
)

// outputSink is the destination for scan reports. os.Stdout satisfies it.
type outputSink = io.Writer

// runNonInteractivePortScan handles a tcpscan invocation supplied with a
// target. Module arguments take precedence when present, otherwise the parsed
// command-line flags are used. It returns whether a non-interactive scan was
// handled and the error, if any.
func runNonInteractivePortScan(args []string, opts CommandLineOptions, output io.Writer) (bool, error) {
	scanOptions, handled, err := resolvePortScanOptions(args, opts)
	if err != nil || !handled {
		return handled, err
	}
	if err := validatePortScanTarget(scanOptions.target); err != nil {
		return true, err
	}
	err = runPortScan(context.Background(), scanOptions, output)
	return true, err
}

func resolvePortScanOptions(args []string, opts CommandLineOptions) (portScanOptions, bool, error) {
	if len(args) > 1 {
		return parsePortScanArgs(args[1:])
	}
	if strings.TrimSpace(opts.portScanTarget) == "" {
		return portScanOptions{}, false, nil
	}
	return portScanOptions{
		target:  strings.TrimSpace(opts.portScanTarget),
		ports:   opts.portScanPorts,
		workers: opts.portScanWorkers,
		json:    opts.portScanJSON,
	}, true, nil
}

// parsePortScanArgs accepts: tcpscan <target> [ports] [workers] [json]
// or named forms: tcpscan -target <cidr> -ports <spec> -workers <n> -json.
func parsePortScanArgs(arguments []string) (portScanOptions, bool, error) {
	options := portScanOptions{}
	for index := 0; index < len(arguments); index++ {
		argument := arguments[index]
		switch {
		case argument == "-json" || argument == "--json":
			options.json = true
		case argument == "-target" || argument == "--target" || argument == "-t":
			next, ok := nextArg(arguments, &index)
			if !ok {
				return options, true, fmt.Errorf("%s requires a value", argument)
			}
			options.target = next
		case argument == "-ports" || argument == "--ports" || argument == "-p":
			next, ok := nextArg(arguments, &index)
			if !ok {
				return options, true, fmt.Errorf("%s requires a value", argument)
			}
			options.ports = next
		case argument == "-workers" || argument == "--workers" || argument == "-w":
			next, ok := nextArg(arguments, &index)
			if !ok {
				return options, true, fmt.Errorf("%s requires a value", argument)
			}
			workers, err := strconv.Atoi(next)
			if err != nil || workers <= 0 {
				return options, true, fmt.Errorf("invalid worker count %q", next)
			}
			options.workers = workers
		case strings.HasPrefix(argument, "-"):
			return options, true, fmt.Errorf("unknown tcpscan argument %q", argument)
		default:
			switch positional(arguments, index) {
			case 0:
				options.target = argument
			case 1:
				options.ports = argument
			case 2:
				workers, err := strconv.Atoi(argument)
				if err != nil || workers <= 0 {
					return options, true, fmt.Errorf("invalid worker count %q", argument)
				}
				options.workers = workers
			default:
				if argument != "json" {
					return options, true, fmt.Errorf("unexpected tcpscan argument %q", argument)
				}
				options.json = true
			}
		}
	}
	if strings.TrimSpace(options.target) == "" {
		return options, false, nil
	}
	return options, true, nil
}

// positional counts only non-flag positional arguments up to index.
func positional(arguments []string, index int) int {
	count := 0
	for _, argument := range arguments[:index] {
		if !strings.HasPrefix(argument, "-") {
			count++
		}
	}
	return count
}

func nextArg(arguments []string, index *int) (string, bool) {
	if *index+1 >= len(arguments) {
		return "", false
	}
	*index++
	return arguments[*index], true
}

func validatePortScanTarget(target string) error {
	if strings.TrimSpace(target) == "" {
		return fmt.Errorf("scan target must not be empty")
	}
	if ip := net.ParseIP(target); ip != nil {
		return nil
	}
	if _, err := portscan.ParseHosts(target); err != nil {
		return fmt.Errorf("invalid scan target %q: %w", target, err)
	}
	return nil
}
