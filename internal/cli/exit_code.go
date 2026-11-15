// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/cliusage"
	"github.com/spf13/cobra"
)

// silenceJSONReportedError keeps cobra from printing "Error: ..." on stderr
// for a coded failure whose --json result on stdout already carries it in
// errors[], so a script that merges the streams still reads one JSON
// document (GAP-2445).
func silenceJSONReportedError(cmd *cobra.Command, jsonOutput bool, err error) {
	var coded *cliusage.ExitCodeError
	if cmd != nil && jsonOutput && errors.As(err, &coded) {
		cmd.SilenceErrors = true
	}
}

// usageFlagErrorExempt lists command trees whose wrong-flag exit status is a
// contract of its own (agent hooks, the notify hook, the watchdog and the
// enterprise lifecycle set theirs, or are read by deployment tooling), so the
// root usage-error mapping leaves them alone.
var usageFlagErrorExempt = []string{"enterprise", "hook", "notify", "watchdog"}

// usageFlagError turns a flag parse error ("unknown flag: --bogus") into a
// usage error with the usage line, a --help pointer and exit status 2, the
// same shape and status the Python defenseclaw CLI uses (GAP-1405).
func usageFlagError(c *cobra.Command, err error) error {
	if c == nil || err == nil {
		return err
	}
	if !c.HasParent() && versionJSONSpelledApart(secretRawArgs()) {
		// GAP-2448: `--version --json` asks for the version document of
		// `--version-json`; it printed a usage error and no JSON.
		return writeMachineVersion(c.OutOrStdout())
	}
	fields := strings.Fields(c.CommandPath())
	for _, f := range fields[min(1, len(fields)):] {
		for _, exempt := range usageFlagErrorExempt {
			if f == exempt {
				// Keep the tree's own exit status; only name a bad flag
				// value plainly (GAP-1989).
				if plain := cliusage.PlainFlagValueError(err); plain != err.Error() {
					return &cliusage.DelegatedUsageError{Msg: plain, Err: err}
				}
				return err
			}
		}
	}
	return cliusage.UsageError(c, err)
}

func init() {
	rootCmd.SetFlagErrorFunc(usageFlagError)
}

// versionJSONSpelledApart reports a command line of exactly --version and
// --json, in either order.
func versionJSONSpelledApart(args []string) bool {
	return len(args) == 2 && ((args[0] == "--version" && args[1] == "--json") || (args[0] == "--json" && args[1] == "--version"))
}
