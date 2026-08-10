// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"flag"
)

// installOptions captures the flags accepted by `defenseclaw-mgr install`
// and `upgrade`. The two subcommands share a struct because upgrade is a
// re-run of install that preserves runtime state — the semantic model is the
// same one packaging/launchd/install-enterprise.sh uses on macOS.
type installOptions struct {
	ConfigPath   string
	ManifestPath string
	LogDir       string
	LogFile      string
	Start        bool
	NoRestart    bool
	JSON         bool
}

func parseInstallOptions(args []string) (installOptions, error) {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	var opts installOptions
	fs.StringVar(&opts.ConfigPath, "config", "", "path to the managed config.yaml to seed into %ProgramData%")
	fs.StringVar(&opts.ManifestPath, "manifest", "", "path to the hook-guardian targets.yaml to seed into %ProgramData%")
	fs.StringVar(&opts.LogDir, "log-dir", "", "override %ProgramData%\\...\\logs")
	fs.StringVar(&opts.LogFile, "log-file", "", "append structured logs to this file (default: <log-dir>\\mgr.log)")
	fs.BoolVar(&opts.Start, "start", false, "register and start the DefenseClawGateway service on success")
	fs.BoolVar(&opts.NoRestart, "norestart", false, "suppress reboot request (a required reboot surfaces as exit 3010)")
	fs.BoolVar(&opts.JSON, "json", false, "emit machine-readable status on stdout")
	// The exe always runs silently, but AVC passes /quiet anyway. Accept and
	// ignore it so custom actions don't have to strip the flag.
	quiet := fs.Bool("quiet", false, "silent mode (implied — this exe never renders UI)")
	if err := fs.Parse(normalizeFlags(args)); err != nil {
		return installOptions{}, err
	}
	_ = quiet
	if opts.ConfigPath == "" {
		return installOptions{}, errors.New("--config is required")
	}
	if opts.ManifestPath == "" {
		return installOptions{}, errors.New("--manifest is required")
	}
	return opts, nil
}

func runInstall(args []string) (int, error) {
	opts, err := parseInstallOptions(args)
	if err != nil {
		return exitUsage, err
	}
	return doInstall(opts, false)
}

func runUpgrade(args []string) (int, error) {
	opts, err := parseInstallOptions(args)
	if err != nil {
		return exitUsage, err
	}
	return doInstall(opts, true)
}

// doInstall performs the fresh-install or upgrade transaction. The Windows
// implementation is a follow-up port of packaging/launchd/install-enterprise.sh
// — snapshot, atomic swap, refuse on trust failure — into
// cmd/defenseclaw-mgr/transaction_windows.go, layered on
// internal/nativeinstallstate and internal/safefile.
func doInstall(_ installOptions, _ bool) (int, error) {
	return exitRetryable, errors.New("install/upgrade transaction not yet implemented — see packaging/windows/PACKAGING.md")
}

// normalizeFlags rewrites `/flag[:value]` and `/flag[=value]` — the MSI-style
// invocation AVC's custom actions produce — into the `--flag[=value]` shape
// Go's flag package accepts. Anything that already starts with `-` is left
// alone.
func normalizeFlags(args []string) []string {
	out := make([]string, 0, len(args))
	for _, a := range args {
		if len(a) == 0 || a[0] != '/' {
			out = append(out, a)
			continue
		}
		rest := a[1:]
		// `/flag:value` → `--flag=value`; `/flag=value` → `--flag=value`;
		// `/flag`       → `--flag`.
		for i, r := range rest {
			if r == ':' || r == '=' {
				out = append(out, "--"+rest[:i]+"="+rest[i+1:])
				rest = ""
				break
			}
		}
		if rest != "" {
			out = append(out, "--"+rest)
		}
	}
	return out
}
