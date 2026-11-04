//go:build darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"context"
	"os"
	"path/filepath"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// codexExecutableCandidates lists where the guardian looks for the user's
// Codex: the user's discovery cache first, then the standard install
// locations.
var codexExecutableCandidates = func(dataDir string) []string {
	candidates := []string{}
	if cached := connector.LoadCachedAgentExecutable(dataDir, "codex"); cached != "" {
		candidates = append(candidates, cached)
	}
	return append(candidates,
		"/Applications/Codex.app/Contents/Resources/codex",
		"/opt/homebrew/bin/codex",
		"/usr/local/bin/codex",
	)
}

// platformPrepareAgentPolicy runs as root before the per-user euid drop.
// For Codex it asks the discovered executable for its effective
// requirements as the user (never inside the drop, where a child could
// regain root) and passes the executable on, so the requirements read
// covers cloud and MDM composition. For Cursor it reports a machine-wide
// hooks.json that registers the same events. Failures are logged and never
// fail the target.
func platformPrepareAgentPolicy(ctx context.Context, connectorName, home, dataDir string, uid, gid int, opts *connector.SetupOpts) {
	if !opts.ManagedEnterprise || os.Geteuid() != 0 {
		return
	}
	switch connectorName {
	case "codex":
		for _, executable := range codexExecutableCandidates(dataDir) {
			executable = filepath.Clean(executable)
			if info, err := os.Stat(executable); err != nil || !info.Mode().IsRegular() {
				continue
			}
			if connector.PreinspectCodexPolicy(ctx, executable, home, uid, gid) == nil {
				opts.AgentExecutable = executable
			}
			return
		}
	case "cursor":
		connector.ReportCursorMachineHooksPolicy()
	}
}
