// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/daemon"
)

// upgradeAuditStoreBeforeStart applies the audit store's pending schema
// migrations in the launcher, before the gateway is launched and its
// readiness clock starts. The first 1.0 start over a long-lived 0.x home
// purges the pre-1.0 history and reclaims the space (migration 33); on a 2 GB
// audit.db that took longer than the 60 s readiness wait, so start stopped
// the gateway mid-migration and setup rolled back the new connectors
// (GAP-1909). Best effort: on any error the gateway applies the migrations
// itself as before and reports the failure.
//
// The terminal gets one line; the upgrade's own lines (each migration
// applied, the purged history's reclaim) go to d's gateway.log,
// where the gateway writes them when it migrates (GAP-0363).
func upgradeAuditStoreBeforeStart(cfg *config.Config, out, warn io.Writer, d *daemon.Daemon) {
	if cfg == nil || strings.TrimSpace(cfg.AuditDB) == "" {
		return
	}
	pending, err := audit.PendingMigrations(cfg.AuditDB)
	if err != nil || pending == 0 {
		return
	}
	fmt.Fprintf(out, "Upgrading the audit database (one time; a large history can take a few minutes)... ")
	var progress bytes.Buffer
	store, err := audit.OpenDaemonStore(cfg.AuditDB, warn, &progress)
	if d != nil {
		_ = d.AppendLog(progress.Bytes())
	}
	if err != nil {
		fmt.Fprintln(out, Style("not finished", "fg=yellow", "bold"))
		fmt.Fprintf(warn, "  %v\n  The gateway retries the upgrade when it starts.\n", err)
		return
	}
	_ = store.Close()
	fmt.Fprintln(out, Style("OK", "fg=green", "bold"))
}
