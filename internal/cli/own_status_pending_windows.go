// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// ownStatusRuntimeResolve is the check the standalone hook makes for the
// caller's own account (the machine policy that registers the SID, then the
// machine runtime selector), run here as the same account; a seam for tests.
// The caller needs no read of the guardian's ledger and no new channel.
var ownStatusRuntimeResolve = enterprisehooks.ResolveWindowsManagedHookRuntime

// ownStatusPendingFor reports, only on positive proof, that the caller's hook
// of connector refuses as enrollment pending: the resolver says no managed
// runtime generation is selected for the account. Any other result, an
// unreadable input included, claims nothing.
func ownStatusPendingFor(connector string) bool {
	executable, err := os.Executable()
	if err != nil {
		return false
	}
	// The hook the account's agents start: the launch image of this bin once
	// Setup staged it (GAP-0751), else the transition image.
	_, err = ownStatusRuntimeResolve(filepath.Clean(winpath.EnterpriseHookLaunchPath(filepath.Dir(executable))), connector)
	if !errors.Is(err, enterprisehooks.ErrWindowsManagedRuntimeGenerationPending) {
		return false
	}
	// Only an account the guardian enrolled for the connector before is
	// blocked; a never-enrolled one keeps its status (GAP-1010).
	home, err := os.UserHomeDir()
	return err == nil && enterpriseHomeConnectorEnrolledBefore(home, connector)
}
