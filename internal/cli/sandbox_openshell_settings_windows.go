// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"context"

	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

// The e2fsprogs settings callback in sandbox.go applies only on a Mac.
func sandboxOpenShellDaemonSettings(context.Context) (sandboxrelay.DaemonSettings, bool) {
	return sandboxrelay.DaemonSettings{}, false
}
