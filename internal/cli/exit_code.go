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

	"github.com/spf13/cobra"
)

// exitCodeError carries the process exit code a command needs the shell to
// see. Windows deployment systems act on the exact code, so a command that
// chooses one must not be flattened to the generic failure result.
type exitCodeError struct {
	code int
	err  error
}

func (e *exitCodeError) Error() string { return e.err.Error() }

func (e *exitCodeError) Unwrap() error { return e.err }

func (e *exitCodeError) ExitCode() int { return e.code }

// withExitCode labels a failure with an exit code, leaving a code an inner
// failure already chose in place.
func withExitCode(err error, code int) error {
	if err == nil {
		return nil
	}
	var coded *exitCodeError
	if errors.As(err, &coded) {
		return err
	}
	return &exitCodeError{code: code, err: err}
}

// commandExitCode reports the exit code a failure asked for, defaulting to the
// generic failure result.
func commandExitCode(err error) int {
	var coded *exitCodeError
	if errors.As(err, &coded) {
		return coded.ExitCode()
	}
	return 1
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
	fields := strings.Fields(c.CommandPath())
	for _, f := range fields[min(1, len(fields)):] {
		for _, exempt := range usageFlagErrorExempt {
			if f == exempt {
				return err
			}
		}
	}
	return usageError(c, err)
}

func init() {
	rootCmd.SetFlagErrorFunc(usageFlagError)
}
