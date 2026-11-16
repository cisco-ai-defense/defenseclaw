// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package mcpasuser

import (
	"context"
	"errors"
	"io"
)

// ErrUnsupported is returned off Windows: only the managed Windows gateway
// starts a user's MCP server through the hook enumerator.
var ErrUnsupported = errors.New("MCP as-user scans run only on managed Windows")

// Serve is Windows only.
func Serve(context.Context, string, Refresher, Starter, func(string, ...any)) error {
	return ErrUnsupported
}

// Dial is Windows only.
func Dial(context.Context, string) (io.ReadWriteCloser, error) { return nil, ErrUnsupported }

// dialRefresh is Windows only.
func dialRefresh(context.Context, string) (io.ReadWriteCloser, error) { return nil, ErrUnsupported }
