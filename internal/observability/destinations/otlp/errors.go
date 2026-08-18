// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

// Package otlp owns generation-local, destination-scoped OTLP transports.
// It never consults OTel environment variables or mutates OTel globals.
package otlp

import (
	"context"
	"errors"

	"github.com/defenseclaw/defenseclaw/internal/netguard"
)

type ErrorCode string

const (
	ErrorInvalidConfig  ErrorCode = "invalid_config"
	ErrorUnsafeEndpoint ErrorCode = "unsafe_endpoint"
	ErrorResolution     ErrorCode = "resolution_failed"
	ErrorTLS            ErrorCode = "tls_failed"
	ErrorInitialization ErrorCode = "initialization_failed"
	ErrorExport         ErrorCode = "export_failed"
	ErrorFlush          ErrorCode = "flush_failed"
	ErrorShutdown       ErrorCode = "shutdown_failed"
)

// Error retains only a closed code and standard context cancellation. It never
// retains endpoints, headers, projected content, resolver text, or backend text.
type Error struct {
	code  ErrorCode
	cause error
}

func (err *Error) Error() string {
	if err == nil {
		return "OTLP destination operation failed"
	}
	return "OTLP destination operation failed: " + string(err.code)
}

func (err *Error) Code() ErrorCode {
	if err == nil {
		return ""
	}
	return err.code
}

func (err *Error) Unwrap() error {
	if err == nil {
		return nil
	}
	return err.cause
}

func newError(code ErrorCode, backend error) error {
	var cause error
	switch {
	case errors.Is(backend, context.Canceled):
		cause = context.Canceled
	case errors.Is(backend, context.DeadlineExceeded):
		cause = context.DeadlineExceeded
	}
	return &Error{code: code, cause: cause}
}

func IsError(err error, code ErrorCode) bool {
	var target *Error
	return errors.As(err, &target) && target.code == code
}

func networkError(err error) error {
	switch {
	case errors.Is(err, netguard.ErrV8AddressProhibited),
		errors.Is(err, netguard.ErrV8EndpointInvalid),
		errors.Is(err, netguard.ErrUnsupportedScheme),
		errors.Is(err, netguard.ErrInlineCredentials):
		return newError(ErrorUnsafeEndpoint, err)
	case errors.Is(err, netguard.ErrV8ResolutionFailed):
		return newError(ErrorResolution, err)
	default:
		return newError(ErrorInitialization, err)
	}
}
