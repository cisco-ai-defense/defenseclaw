// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"io"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// Only the standalone Windows guardian records the targets it put back
// (GAP-0440); Secure Client is unchanged.
func init() {
	enterpriseHookGuardianRestoresEnabled = enterprisehooks.WindowsStandaloneProcess
}

// recordEnterpriseHookStandaloneUnixRestores is Linux and macOS only; the
// standalone Unix guardian never runs here.
func recordEnterpriseHookStandaloneUnixRestores(io.Writer, string, time.Time, enterpriseHookReconcileRun) {
}
