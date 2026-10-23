// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"fmt"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"golang.org/x/sys/windows"
)

// The Windows managed profile delivers Codex and Claude Code through machine
// policy and serves them from the gateway service; it writes no native OTLP
// exporter into the account's own agent configuration. An exporter an earlier
// per-user install left there still names that install's port. No DefenseClaw
// process of the account holds that port, so another account can bind it and
// receive the agent's prompt telemetry and bearer (GAP-0836). Verify reports
// such an exporter so the guardian's next reconcile, including the one at
// service start, repairs the row; install removes it as the target user.

// windowsManagedUserNativeOTLPAbsent fails while the account's configuration
// keeps a DefenseClaw native exporter. The error names fields, never values.
func windowsManagedUserNativeOTLPAbsent(connectorName, home, dataDir string, target *windows.SID) error {
	var residue []string
	err := connector.WithUserHomeDir(home, func() error {
		return windowsEnterpriseTargetImpersonation(target, home, func() error {
			var err error
			residue, err = connector.UserNativeOTLPResidue(connectorName, connector.SetupOpts{
				DataDir:           dataDir,
				ManagedEnterprise: true,
			})
			return err
		})
	})
	if err != nil {
		return fmt.Errorf("enterprise hooks: inspect %s native OTLP settings: %w", connectorName, err)
	}
	if len(residue) > 0 {
		return fmt.Errorf(
			"enterprise hooks: %s keeps a native OTLP exporter from an earlier per-user install (%s); "+
				"the managed gateway does not serve it, so another account could receive its telemetry; repair removes it",
			connectorName,
			strings.Join(residue, ", "),
		)
	}
	return nil
}

// removeWindowsManagedUserNativeOTLP removes that exporter and its credential
// as the target user.
func removeWindowsManagedUserNativeOTLP(connectorName, home, dataDir string, target *windows.SID) error {
	err := connector.WithUserHomeDir(home, func() error {
		return windowsEnterpriseTargetImpersonation(target, home, func() error {
			_, err := connector.RemoveUserNativeOTLP(connectorName, connector.SetupOpts{
				DataDir:           dataDir,
				ManagedEnterprise: true,
			})
			return err
		})
	})
	if err != nil {
		return fmt.Errorf("enterprise hooks: remove %s native OTLP exporter from an earlier per-user install: %w", connectorName, err)
	}
	return nil
}
