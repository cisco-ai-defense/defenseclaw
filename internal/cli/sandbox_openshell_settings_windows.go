// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"context"
	"errors"

	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

// The e2fsprogs settings callback in sandbox.go applies only on a Mac.
func sandboxOpenShellDaemonSettings(context.Context) (sandboxrelay.DaemonSettings, bool) {
	return sandboxrelay.DaemonSettings{}, false
}

// sandboxManagedAccountPolicy has no managed gateway hook socket to ask on
// Windows, where sandboxes do not run.
func sandboxManagedAccountPolicy(context.Context, string) (*sandboxapi.ManagedExplain, error) {
	return nil, errors.New("sandboxes do not run on Windows")
}
