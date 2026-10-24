// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
// Verify is read-only and never impersonates, so it reads the account's files
// only when no reparse point lies on their path; a linked config is checked by
// the repair that runs as the target user.
func windowsManagedUserNativeOTLPAbsent(connectorName, home, dataDir string, _ *windows.SID) error {
	for _, path := range windowsManagedUserNativeOTLPPaths(connectorName, home, dataDir) {
		if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err := rejectWindowsReparseChain(path); err != nil {
			return nil
		}
	}
	var residue []string
	err := connector.WithUserHomeDir(home, func() error {
		var err error
		residue, err = connector.UserNativeOTLPResidue(connectorName, connector.SetupOpts{
			DataDir:           dataDir,
			ManagedEnterprise: true,
		})
		return err
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

// windowsManagedUserNativeOTLPPaths are the files the residue check reads.
func windowsManagedUserNativeOTLPPaths(connectorName, home, dataDir string) []string {
	switch connectorName {
	case "codex":
		return []string{
			filepath.Join(home, ".codex", "config.toml"),
			filepath.Join(dataDir, "codex_config_backup.json"),
		}
	case "claudecode":
		return []string{
			filepath.Join(home, ".claude", "settings.json"),
			filepath.Join(dataDir, "claudecode_backup.json"),
		}
	default:
		return nil
	}
}

// removeWindowsManagedUserNativeOTLPAsTarget removes that exporter and its
// credential. The caller runs it as the target user with the account's home
// bound (connector.WithUserHomeDir) and hardens the data directory afterwards:
// the atomic edit protects its state directory there with the per-user DACL.
//
// The cleanup is best-effort (GAP-1103): an account with nothing to take back
// opens no transaction, and a removal that fails is reported, never an install
// failure that rolls the upgrade back. Verify keeps reporting an exporter that
// stays, and the next repair retries it.
func removeWindowsManagedUserNativeOTLPAsTarget(connectorName, dataDir string) error {
	opts := connector.SetupOpts{DataDir: dataDir, ManagedEnterprise: true}
	if residue, err := connector.UserNativeOTLPResidue(connectorName, opts); err == nil && len(residue) == 0 {
		return nil
	}
	if _, err := connector.RemoveUserNativeOTLP(connectorName, opts); err != nil {
		fmt.Fprintf(os.Stderr, "defenseclaw: enterprise hooks: could not remove the %s native OTLP exporter an earlier per-user install left (%v); verify reports it and repair retries\n", connectorName, err)
	}
	return nil
}
