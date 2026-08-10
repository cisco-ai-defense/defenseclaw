// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"flag"
)

type uninstallOptions struct {
	Purge     bool
	LogFile   string
	NoRestart bool
	JSON      bool
}

func parseUninstallOptions(args []string) (uninstallOptions, error) {
	fs := flag.NewFlagSet("uninstall", flag.ContinueOnError)
	var opts uninstallOptions
	fs.BoolVar(&opts.Purge, "purge", false, "also delete %ProgramData%\\...\\ (config, audit DB, device.key)")
	fs.StringVar(&opts.LogFile, "log-file", "", "append structured logs to this file")
	fs.BoolVar(&opts.NoRestart, "norestart", false, "suppress reboot request")
	fs.BoolVar(&opts.JSON, "json", false, "emit machine-readable status on stdout")
	quiet := fs.Bool("quiet", false, "silent mode (implied)")
	if err := fs.Parse(normalizeFlags(args)); err != nil {
		return uninstallOptions{}, err
	}
	_ = quiet
	return opts, nil
}

func runUninstall(args []string) (int, error) {
	opts, err := parseUninstallOptions(args)
	if err != nil {
		return exitUsage, err
	}
	return doUninstall(opts)
}

// doUninstall stops and unregisters the service, removes the install root,
// and — when --purge is set — deletes %ProgramData%\...\ as well. The
// Windows implementation is a follow-up port of packaging/macos/uninstall.sh
// layered on internal/nativeinstallstate + service_windows.go.
func doUninstall(_ uninstallOptions) (int, error) {
	return exitRetryable, errors.New("uninstall not yet implemented — see packaging/windows/PACKAGING.md")
}
