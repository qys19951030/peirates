package app

import (
	"fmt"
	"os"
	"strings"

	"github.com/inguardians/peirates/internal/modules"
)

func canonicalModuleCommand(input string) string { return CanonicalCommand(input) }

var moduleCommandAliases = commandAliases

// runModuleCommand preserves registry dispatch and handles cloud token inline options.
func runModuleCommand(registry *modules.Registry, session *Session, input string) (modules.Result, bool) {
	fields := strings.Fields(input)
	if len(fields) > 1 {
		command := canonicalModuleCommand(fields[0])
		switch command {
		case "azure-get-token", "aws-get-eks-node-token":
			args, err := parseCommandArgs(input)
			if err != nil {
				label := "Azure token"
				if command == "aws-get-eks-node-token" {
					label = "EKS node token"
				}
				fmt.Fprintf(os.Stdout, "[-] %s: %v\n", label, err)
			} else if command == "aws-get-eks-node-token" {
				requestAWSNodeToken(session, args[1:], os.Stdout)
			} else {
				requestAzureToken(session, args[1:], os.Stdin, os.Stdout)
			}
			return modules.Continue, true
		case "tcpscan":
			args, err := parseCommandArgs(input)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[-] port scan failed: %v\n", err)
				return modules.Continue, true
			}
			if handled, scanErr := runNonInteractivePortScan(args, portScanFlagOptions, os.Stdout); scanErr != nil {
				fmt.Fprintf(os.Stderr, "[-] port scan failed: %v\n", scanErr)
			} else if !handled {
				tcpScan(session.Interactive)
			}
			return modules.Continue, true
		}
	}
	return registry.Run(canonicalModuleCommand(input))
}
