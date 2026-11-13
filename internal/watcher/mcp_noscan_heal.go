// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

// Before the GAP-0088 fix the rescan wrote some MCP baselines plain without a
// scan: an allow without a scan or a failed scan whose mark the failed drift
// scan dropped, and a policy refusal recorded plain. The hook reads a plain
// baseline as a decided admission, so after an upgrade to 1.0.10 such a
// server kept running whatever the policy now said (a fail-open the fix alone
// did not undo).
//
// When the watcher of a data directory first starts on 1.0.10, it marks every
// stored MCP baseline that is plain and has no scan as owing an admission
// (mcpAdmissionOwedMark), whatever the servers listed at that moment: on a
// managed host the list comes from the hooks and is empty at start. A marked
// server counts as failed, so the hook refuses its calls where MCP admission
// fails closed (strict, managed) and warns in the OSS default and permissive
// tiers, until admission runs again under the current policy: at the next
// rescan of a listed server, or within the discovery poll once a hook reports
// it. An allow rule then admits it without a scan, a deny refuses it, and a
// scan decides as for a new server. The pass runs once: a row of type
// mcpNoScanHealType records it with one upgrade audit row. A store it could
// not finish (a read or write error, more than mcpNoScanHealMaxRows records)
// is not recorded, and the next start goes on; the marks it wrote stay.
// After a 0.8.x upgrade the bridge first baselines the servers the earlier
// release ran (GAP-1227); the next start marks the ones its scan left plain.

// mcpAdmissionOwedMark ends the fingerprint of an MCP baseline the 1.0.10
// pass found plain without a scan.
const mcpAdmissionOwedMark = "|mcp-admission-owed"

// mcpNoScanHealType is the target_snapshots type of the row recording that
// the pass is done; its path is mcpNoScanHealVersion.
const (
	mcpNoScanHealType    = "mcp_noscan_heal"
	mcpNoScanHealVersion = "1.0.10"
)

// mcpNoScanHealMaxRows bounds the records one start reads. Replaceable in
// tests.
var mcpNoScanHealMaxRows = 10000

// mcpAdmissionOwed reports a baseline the pass marked.
func mcpAdmissionOwed(baseline *audit.SnapshotRow) bool {
	return baseline != nil && strings.HasSuffix(baseline.ScannerFingerprint, mcpAdmissionOwedMark)
}

// mcpFingerprintPlain reports an MCP baseline fingerprint that records no
// admission without a scan, no failed or refused scan and no unfinished or
// unenforced admission.
func mcpFingerprintPlain(fingerprint string) bool {
	for _, mark := range []string{
		admittedWithoutScanMark, unverifiedMCPMark, mcpScanFailedMark, mcpLauncherRefusedMark,
		mcpPolicyRefusedMark, mcpAdmissionOwedMark, unenforcedRejectionMark, interruptedAdmissionMark,
	} {
		if strings.HasSuffix(fingerprint, mark) {
			return false
		}
	}
	return true
}

// markMCPNoScanAdmissionsOwed runs the pass, once per data directory. It does
// not apply without a store, with MCP admission off, under Secure Client
// (issue #1092), or while a 0.8.x bridge has yet to baseline its servers.
func (w *InstallWatcher) markMCPNoScanAdmissionsOwed() {
	if w.store == nil || !w.admitNewMCP || w.secureClientActive() || w.pendingMCPUpgradeBaseline() != "" {
		return
	}
	if _, err := w.store.GetTargetSnapshot(mcpNoScanHealType, mcpNoScanHealVersion); !errors.Is(err, sql.ErrNoRows) {
		return
	}
	paths, err := w.store.ListTargetSnapshotPaths(string(InstallMCP))
	if err != nil {
		fmt.Fprintf(os.Stderr, "[watcher] list the MCP baselines of the 1.0.10 upgrade pass: %v\n", err)
		return
	}
	owed, complete := 0, true
	if len(paths) > mcpNoScanHealMaxRows {
		fmt.Fprintf(os.Stderr, "[watcher] %d MCP baselines, over the %d one start reads; the 1.0.10 upgrade pass goes on at the next start\n", len(paths), mcpNoScanHealMaxRows)
		paths, complete = paths[:mcpNoScanHealMaxRows], false
	}
	for _, path := range paths {
		row, err := w.store.GetTargetSnapshot(string(InstallMCP), path)
		if err != nil {
			complete = false
			continue
		}
		if row.ScanID != "" || !mcpFingerprintPlain(row.ScannerFingerprint) {
			continue
		}
		if err := w.store.SetTargetSnapshot(row.TargetType, row.TargetPath, row.ContentHash, row.DependencyHashes,
			row.ConfigHashes, row.NetworkEndpoints, "", row.ScannerFingerprint+mcpAdmissionOwedMark); err != nil {
			complete = false
			continue
		}
		// An outcome this process already read from the old baseline
		// gives way to the owed admission.
		w.noteMCPBaseline(row.TargetPath, row.ContentHash, row.ScannerFingerprint+mcpAdmissionOwedMark)
		owed++
	}
	if owed > 0 {
		fmt.Fprintf(os.Stderr, "[watcher] %d MCP servers recorded without a scan by an earlier release owe an admission (GAP-0088)\n", owed)
	}
	if !complete {
		return
	}
	if err := w.store.SetTargetSnapshot(mcpNoScanHealType, mcpNoScanHealVersion, "", "{}", "{}", "[]", "", ""); err != nil {
		fmt.Fprintf(os.Stderr, "[watcher] record the 1.0.10 upgrade pass: %v\n", err)
		return
	}
	if w.logger != nil {
		_ = w.logger.LogAction(string(audit.ActionUpgrade), "mcp-baselines",
			fmt.Sprintf("type=mcp migration=noscan-baseline-heal version=%s owed=%d (gas-ux-r2:GAP-0088)", mcpNoScanHealVersion, owed))
	}
}
