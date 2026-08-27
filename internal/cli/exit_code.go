// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// SPDX-License-Identifier: Apache-2.0

package cli

import "errors"

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
