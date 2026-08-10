// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Command defenseclaw-mgr is the machine-level lifecycle CLI for
// DefenseClaw on Windows. AVC's WiX MSI invokes this binary silently from
// custom actions for install, upgrade, uninstall, and service control.
//
// Every subcommand is silent by contract — the binary never renders UI. The
// documented AVC surface lives in packaging/windows/PACKAGING.md; the exit
// codes are shared with cmd/defenseclaw-setup so per-user Setup and the
// managed lifecycle exe report failures identically to deployment tooling.
package main

import (
	"fmt"
	"os"
	"strings"
)

const (
	// Exit codes — kept in lockstep with cmd/defenseclaw-setup/main.go so a
	// single deployment policy in AVC's MSI covers both products.
	exitOK                  = 0
	exitUserCancelled       = 1602
	exitRetryable           = 1603
	exitAnotherInProgress   = 1618
	exitRestartRequired     = 3010
	exitUsage               = 2
	exitUnsupportedPlatform = 1
)

// subcommand dispatches the user's subcommand. Each handler returns the
// process exit code plus an optional error to write to stderr.
type subcommand func(args []string) (int, error)

var subcommands = map[string]subcommand{
	"install":   runInstall,
	"upgrade":   runUpgrade,
	"uninstall": runUninstall,
	"service":   runService,
	"verify":    runVerify,
	"help":      runHelp,
	"--help":    runHelp,
	"-h":        runHelp,
}

func main() {
	if err := requireSupportedPlatform(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(exitUnsupportedPlatform)
	}
	args := os.Args[1:]
	if len(args) == 0 {
		printUsage(os.Stderr)
		os.Exit(exitUsage)
	}
	name := strings.ToLower(args[0])
	handler, ok := subcommands[name]
	if !ok {
		fmt.Fprintf(os.Stderr, "defenseclaw-mgr: unknown subcommand %q\n\n", args[0])
		printUsage(os.Stderr)
		os.Exit(exitUsage)
	}
	code, err := handler(args[1:])
	if err != nil {
		// Silent mode suppresses interactive UI, not diagnostics — AVC's
		// custom-action logging captures stderr, and a machine-level
		// failure with no message is impossible to triage.
		fmt.Fprintf(os.Stderr, "defenseclaw-mgr %s: %v\n", name, err)
		if code == exitOK {
			code = exitRetryable
		}
	}
	os.Exit(code)
}

func runHelp(_ []string) (int, error) {
	printUsage(os.Stdout)
	return exitOK, nil
}

func printUsage(w *os.File) {
	fmt.Fprint(w, usage)
}

const usage = `defenseclaw-mgr — machine-level lifecycle for DefenseClaw on Windows

Usage:
  defenseclaw-mgr <subcommand> [flags]

Subcommands:
  install     Fresh install. Lays down %ProgramFiles%\Cisco\Cisco Secure
              Client\DefenseClaw, seeds %ProgramData% config, optionally
              registers and starts the DefenseClawGateway service.
  upgrade     Idempotent re-run of install. Preserves runtime state.
  uninstall   Stop and unregister the service, remove install root.
              --purge also removes %ProgramData% config and audit data.
  service     Manage the DefenseClawGateway SCM entry:
                register | unregister | start | stop | status
  verify      Post-install validation (Authenticode, layout, ACLs).
  help        Print this help.

Global flags (accepted by every subcommand):
  /quiet          Silent (implied — this binary never renders UI).
  /norestart      Suppress the reboot request. Reboots surface as exit 3010.
  --log-file P    Append structured logs to P (default:
                  %ProgramData%\Cisco\Cisco Secure Client\DefenseClaw\logs\mgr.log).
  --json          Emit machine-readable status on stdout.

Exit codes:
  0     Success.
  1602  Cancelled.
  1603  Retryable failure — operation incomplete, safe to retry.
  1618  Another lifecycle operation is already in progress.
  3010  Success but reboot required.

See packaging/windows/PACKAGING.md for the full AVC contract.
`
