// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"io"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

// upgradeAuditStoreBeforeStart applies the audit store's pending schema
// migrations in the launcher, before the gateway is launched and its
// readiness clock starts. The first 1.0 start over a long-lived 0.x home
// purges the pre-1.0 history and reclaims the space (migration 33); on a 2 GB
// audit.db that took longer than the 60 s readiness wait, so start stopped
// the gateway mid-migration and setup rolled back the new connectors
// (GAP-1909). Best effort: on any error the gateway applies the migrations
// itself as before and reports the failure.
func upgradeAuditStoreBeforeStart(cfg *config.Config, out, warn io.Writer) {
	if cfg == nil || strings.TrimSpace(cfg.AuditDB) == "" {
		return
	}
	pending, err := audit.PendingMigrations(cfg.AuditDB)
	if err != nil || pending == 0 {
		return
	}
	fmt.Fprintf(out, "Upgrading the audit database (one time; a large history can take a few minutes)... ")
	opts := auditStoreOptions(cfg)
	upgrade := func(path string, warn io.Writer) error { return audit.UpgradeDaemonStore(path, warn, opts...) }
	if cfg.SecureClientIntegration() {
		// Secure Client keeps the upgrade of main, whose per-migration notes
		// go to stderr (issue #1092).
		upgrade = func(path string, warn io.Writer) error {
			store, err := audit.OpenDaemonStore(path, warn, opts...)
			if err != nil {
				return err
			}
			return store.Close()
		}
	}
	if err := upgrade(cfg.AuditDB, warn); err != nil {
		fmt.Fprintln(out, Style("not finished", "fg=yellow", "bold"))
		fmt.Fprintf(warn, "  %v\n  The gateway retries the upgrade when it starts.\n", err)
		return
	}
	fmt.Fprintln(out, Style("OK", "fg=green", "bold"))
}
