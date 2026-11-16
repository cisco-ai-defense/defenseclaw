// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package refusalpipe

import (
	"context"
	"errors"
)

// Send is a no-op off Windows: the Unix standalone gateway authenticates the
// hook socket caller itself and audits its refusals.
func Send(context.Context, Report) error { return nil }

// OwnStatus is Windows only: a Linux or macOS standard user reads their own
// state on the hook socket (managed.OwnStatus).
func OwnStatus(context.Context) ([]byte, error) {
	return nil, errors.New("the own-status pipe is Windows only")
}

// AccountExcluded is Windows only: the Unix hook socket authenticates the
// caller and the gateway judges the exclusion itself.
func AccountExcluded(context.Context) (bool, error) {
	return false, errors.New("the exclusion pipe is Windows only")
}
