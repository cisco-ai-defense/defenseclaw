// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/legacyconnector"
)

// migrateRetiredConnectorState finishes moving the retired Desktop connector
// ID to its replacement. The config loader already renamed the ID in memory
// (Config.LegacyConnectorNotices); this removes what an older release left on
// the host so the replacement's normal Setup runs against a clean roster:
// DefenseClaw's entries in the legacy hooks file, its scripts and backup, the
// lock entry, and the active-roster entry.
//
// It runs before any connector transaction captures state, and only when
// there is something to do: a config notice, the retired ID in the roster or
// lock, its backup directory, its scripts, or DefenseClaw entries still in the
// legacy hooks file. Cleanup problems are logged, never fatal: protecting
// Devin must not wait on a file DefenseClaw no longer owns.
func (s *Sidecar) migrateRetiredConnectorState(ctx context.Context, registry *connector.Registry) {
	cfg := s.currentConfig()
	if cfg == nil || strings.TrimSpace(cfg.DataDir) == "" {
		return
	}
	dataDir := cfg.DataDir
	retiredID := legacyconnector.RetiredDesktopID
	retired, _ := connector.RetiredConnector(retiredID)
	opts := connector.SetupOpts{DataDir: dataDir, WorkspaceDir: cfg.ConnectorWorkspaceDir()}

	inRoster := false
	for _, name := range connector.LoadActiveConnectors(dataDir) {
		if legacyconnector.IsRetired(name) {
			inRoster = true
			break
		}
	}
	pending := len(cfg.LegacyConnectorNotices) > 0 || inRoster ||
		connector.LoadHookContractLockEntry(dataDir, retiredID).Connector != "" ||
		pathExists(legacyconnector.BackupDir(dataDir)) ||
		retired.(connector.RetiredCleanupReporter).HasResidue(opts)
	if !pending {
		return
	}

	teardownErr := retired.Teardown(ctx, opts)
	verifyErr := retired.VerifyClean(opts)
	if inRoster {
		if _, err := connector.MarkConnectorInactive(dataDir, retiredID); err != nil {
			fmt.Fprintf(os.Stderr, "[guardrail] WARNING: drop retired connector %s from the active roster: %v\n", retiredID, err)
		}
	}
	RemoveConnectorRulePackOverrides(retiredID)

	report := retired.(connector.RetiredCleanupReporter).LastCleanup()
	fmt.Fprintln(os.Stderr, "[guardrail] "+retiredConnectorMigrationLine(cfg.LegacyConnectorNotices, report, s.devinHooksPathForLog(registry, opts)))
	for _, err := range []error{teardownErr, verifyErr} {
		if err != nil {
			fmt.Fprintf(os.Stderr, "[guardrail] WARNING: retired connector %s cleanup: %v; %s\n", retiredID, err, removedConnectorDocHint)
		}
	}
	if s.logger != nil {
		_ = s.logger.LogAction(
			string(audit.ActionSetupHookConnector),
			legacyconnector.Replacement,
			fmt.Sprintf("connector=%s action=migrate-retired from=%s removed_hook_entries=%d", legacyconnector.Replacement, retiredID, report.RemovedEntries),
		)
	}
}

// retiredConnectorMigrationLine is the single operator-facing log line for
// the migration.
func retiredConnectorMigrationLine(notices []string, report connector.RetiredCleanupReport, devinPath string) string {
	var b strings.Builder
	if len(notices) > 0 {
		b.WriteString(strings.Join(notices, "; "))
	} else {
		b.WriteString(legacyconnector.Headline + ": removed state left by the retired connector ID")
	}
	hooksPath := report.HooksPath
	if hooksPath == "" {
		hooksPath = "the legacy Cascade hooks file"
	}
	fmt.Fprintf(&b, "; removed %d DefenseClaw hook entries from %s.", report.RemovedEntries, hooksPath)
	if strings.TrimSpace(devinPath) == "" {
		devinPath = "the Devin config"
	}
	fmt.Fprintf(&b, " Devin CLI and Devin Desktop's Devin Local agent are protected via %s; Cascade conversations are not protected.", devinPath)
	return b.String()
}

func (s *Sidecar) devinHooksPathForLog(registry *connector.Registry, opts connector.SetupOpts) string {
	if registry == nil {
		return ""
	}
	devin, ok := registry.Get(legacyconnector.Replacement)
	if !ok {
		return ""
	}
	if home, err := s.connectorLifecycleConfigHome(devin); err == nil {
		opts.ConfigHome = home
	}
	paths := connector.HookConfigPathsForConnector(devin, opts)
	if len(paths) == 0 {
		return ""
	}
	return paths[0]
}

func pathExists(path string) bool {
	if strings.TrimSpace(path) == "" {
		return false
	}
	_, err := os.Lstat(path)
	return err == nil
}
