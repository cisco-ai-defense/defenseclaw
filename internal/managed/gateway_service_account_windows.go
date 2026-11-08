//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"os"
	"strings"
)

// GatewayServiceAccount is the NT SERVICE account that may write the managed
// runtime tree, for a reader of a service-written runtime file. The gateway
// and guardian services carry it as the WindowsServiceAccountEnv pin in their
// registry Environment; a console the administrator opened (enterprise
// windows status, verify, doctor) carries no such pin, so a reader that took
// only the environment refused the Modify entry the gateway service holds on
// runtime\ and inherits onto the files it writes (GAP-0081). A standalone
// process without the pin gets the account the installer registers for the
// standalone gateway service (StandaloneLayout.ServiceUser), the single
// source of that name. Every other process, Secure Client included, keeps the
// pin alone, so an unpinned process stays on the administrator-only rule.
func GatewayServiceAccount() string {
	if account := strings.TrimSpace(os.Getenv(WindowsServiceAccountEnv)); account != "" {
		return account
	}
	if windowsStandaloneTrustScope() {
		return `NT SERVICE\` + StandaloneWindowsGatewaySvc
	}
	return ""
}
