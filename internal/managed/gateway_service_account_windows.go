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
// windows status, verify, doctor, hooks verify) carries no such pin, so a
// reader that took only the environment refused the Modify entry the gateway
// service holds on the runtime folder and inherits onto the files it writes
// (GAP-0081).
//
// An unpinned binary that sits in a standalone install root gets the gateway
// service the installer registered for that root and no other: the
// production account for the production root, the run-scoped account for a
// certification root. The account is derived from the protected install
// location of the running binary, never from a name the caller supplies. A
// process outside every install root, Secure Client included, keeps the pin
// alone, so an unpinned process there stays on the administrator-only rule.
func GatewayServiceAccount() string {
	if account := strings.TrimSpace(os.Getenv(WindowsServiceAccountEnv)); account != "" {
		return account
	}
	if service := windowsStandaloneInstallService(); service != "" {
		return `NT SERVICE\` + service
	}
	return ""
}
