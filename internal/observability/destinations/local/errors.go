// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

// Package local implements generation-owned local observability destination
// adapters. Adapters in this package receive only immutable destination
// projections from delivery.Batch; they never redact, classify, or inspect a
// canonical observability record.
package local

import "errors"

// ErrorCode is a bounded, content-free constructor or lifecycle failure.
type ErrorCode string

const (
	ErrorInvalidConfig ErrorCode = "invalid_config"
	ErrorUnsafePath    ErrorCode = "unsafe_path"
	ErrorOpenFailed    ErrorCode = "open_failed"
	ErrorClosed        ErrorCode = "closed"
)

// Error deliberately carries no path, projected content, or operating-system
// diagnostic. Optional-destination failures are safe to include in mandatory
// platform-health records.
type Error struct{ code ErrorCode }

func (err *Error) Error() string {
	if err == nil {
		return "local observability destination rejected"
	}
	return "local observability destination rejected: " + string(err.code)
}

// Code returns the bounded failure identity.
func (err *Error) Code() ErrorCode {
	if err == nil {
		return ""
	}
	return err.code
}

func newError(code ErrorCode) error { return &Error{code: code} }

// IsError reports whether err has the requested bounded code.
func IsError(err error, code ErrorCode) bool {
	var target *Error
	return errors.As(err, &target) && target.code == code
}

// secureFailure is intentionally content-free. unsafe distinguishes a path
// identity/trust failure (which cannot become safe through delivery retries)
// from an ordinary local I/O failure.
type secureFailure struct{ unsafe bool }

func (*secureFailure) Error() string { return "secure local file operation failed" }

func unsafeFailure() error { return &secureFailure{unsafe: true} }
func ioFailure() error     { return &secureFailure{} }

func isUnsafeFailure(err error) bool {
	var failure *secureFailure
	return errors.As(err, &failure) && failure.unsafe
}
