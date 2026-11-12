// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// windowsSecureClientHealthReportDataDir is the Secure Client gateway's
// data_dir (<StateRoot>\runtime) for a lifecycle run: the certification
// --state-root when one is given, else the trusted production state root.
// A seam for tests.
var windowsSecureClientHealthReportDataDir = func(opts *windowsEnterpriseLifecycleOptions) string {
	stateRoot := ""
	if opts != nil {
		stateRoot = strings.TrimSpace(opts.stateRoot)
	}
	if stateRoot == "" {
		roots, err := winpath.TrustedEnterpriseRoots(winpath.EnterpriseProfileSecureClient)
		if err != nil {
			return ""
		}
		stateRoot = roots.StateRoot
	}
	return filepath.Join(stateRoot, "runtime")
}

// runWindowsSecureClientLifecycle runs a Secure Client installer action.
// An elevated status also reports the gateway's last endpoint health report:
// with --json as a "health_report" member of the installer's document, as
// text as one line after its summary. Without a report the run is exactly
// the installer's. The report never changes ok or the exit code.
func runWindowsSecureClientLifecycle(
	ctx context.Context,
	cmd *cobra.Command,
	action string,
	opts *windowsEnterpriseLifecycleOptions,
	script string,
	args []string,
) error {
	var state *enterprisestatus.HealthReportState
	if action == "status" && windowsEnterpriseIsElevated() {
		state = enterprisestatus.ReadHealthReport(windowsSecureClientHealthReportDataDir(opts), time.Now())
	}
	if state == nil {
		return windowsEnterpriseCommandRunner(ctx, cmd, script, args)
	}
	if opts == nil || !opts.jsonOutput {
		err := windowsEnterpriseCommandRunner(ctx, cmd, script, args)
		fmt.Fprintf(cmd.OutOrStdout(), "  Health report: %s\n", state.Summary())
		return err
	}
	// The relay prints the document once, after the installer exits, so
	// holding stdout until then delays nothing.
	stdout := cmd.OutOrStdout()
	var held bytes.Buffer
	cmd.SetOut(&held)
	err := windowsEnterpriseCommandRunner(ctx, cmd, script, args)
	restoreWindowsCommandOutput(cmd, stdout)
	_, _ = stdout.Write(injectWindowsSecureClientHealthReport(held.Bytes(), state))
	return err
}

// restoreWindowsCommandOutput puts back the writer OutOrStdout returned
// before; os.Stdout is restored as unset, so OutOrStderr keeps its default.
func restoreWindowsCommandOutput(cmd *cobra.Command, previous io.Writer) {
	if previous == io.Writer(os.Stdout) {
		cmd.SetOut(nil)
		return
	}
	cmd.SetOut(previous)
}
