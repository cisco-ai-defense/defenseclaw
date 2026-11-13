// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

// Before the GAP-0088 fix the rescan wrote some MCP baselines plain without a
// scan: an allow without a scan or a failed scan whose mark the failed drift
// scan dropped, and a policy refusal recorded as plain. The hook reads a
// plain baseline as a decided admission, so an upgrade to 1.0.10 kept such a
// server running whatever the policy now says (a fail-open the fix alone did
// not undo). The first complete rescan cycle of a data directory on 1.0.10
// admits each of these again under the current policy, as a new server is:
// an allow rule admits it without a scan, a deny refuses it, and a scan that
// fails blocks it where MCP admission fails closed (strict, managed) and keeps
// it with a warning in the OSS default and permissive tiers. It runs once:
// a row of type mcpNoScanHealType records that it is done, and an upgrade
// audit row names how many servers it admitted again. A cycle admits at most
// mcpNoScanHealPerCycle of them; a pass with more left goes on at the next
// cycle and is recorded done only after a cycle that finished it.

// mcpNoScanHealType is the target_snapshots type of the row recording that
// the pass is done; its path is mcpNoScanHealVersion.
const (
	mcpNoScanHealType    = "mcp_noscan_heal"
	mcpNoScanHealVersion = "1.0.10"
)

// mcpNoScanHealPerCycle bounds how many servers one cycle admits again.
// Replaceable in tests.
var mcpNoScanHealPerCycle = 32

type mcpNoScanHealPass struct {
	healed   int
	deferred bool
}

// pendingMCPNoScanHeal returns the pass of this cycle, or nil when it is done
// or does not apply: no store, MCP admission off, Secure Client (issue
// #1092), or the cycle that baselines the MCP servers of a 0.8.x upgrade,
// whose bridge keeps the servers the earlier release ran at the first start
// (GAP-1227); the next cycle heals them as any other.
func (w *InstallWatcher) pendingMCPNoScanHeal() *mcpNoScanHealPass {
	if w.store == nil || !w.admitNewMCP || w.secureClientActive() || w.mcpUpgradeBaseline != "" {
		return nil
	}
	if _, err := w.store.GetTargetSnapshot(mcpNoScanHealType, mcpNoScanHealVersion); !errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	return &mcpNoScanHealPass{}
}

// mcpFingerprintPlain reports an MCP baseline fingerprint that records no
// admission without a scan, no failed or refused scan and no unfinished or
// unenforced admission.
func mcpFingerprintPlain(fingerprint string) bool {
	for _, mark := range []string{
		admittedWithoutScanMark, unverifiedMCPMark, mcpScanFailedMark, mcpLauncherRefusedMark,
		mcpPolicyRefusedMark, unenforcedRejectionMark, interruptedAdmissionMark,
	} {
		if strings.HasSuffix(fingerprint, mark) {
			return false
		}
	}
	return true
}

// healsMCPNoScanBaseline reports, and counts, an MCP baseline the pass admits
// again: plain and without a scan. Past the bound of the cycle it defers.
func (w *InstallWatcher) healsMCPNoScanBaseline(evt InstallEvent, baseline *audit.SnapshotRow) bool {
	pass := w.mcpNoScanHeal
	if pass == nil || evt.Type != InstallMCP || baseline == nil || baseline.ScanID != "" ||
		!mcpFingerprintPlain(baseline.ScannerFingerprint) {
		return false
	}
	if pass.healed >= mcpNoScanHealPerCycle {
		pass.deferred = true
		return false
	}
	pass.healed++
	fmt.Fprintf(os.Stderr, "[rescan] mcp %s has a baseline without a scan from an earlier release; running install admission (GAP-0088)\n", evt.Name)
	return true
}

// finishMCPNoScanHeal records the pass done after a complete cycle that left
// nothing deferred, with one upgrade audit row.
func (w *InstallWatcher) finishMCPNoScanHeal(ctx context.Context) {
	pass := w.mcpNoScanHeal
	if pass == nil || pass.deferred || ctx.Err() != nil {
		return
	}
	if err := w.store.SetTargetSnapshot(mcpNoScanHealType, mcpNoScanHealVersion, "", "{}", "{}", "[]", "", ""); err != nil {
		fmt.Fprintf(os.Stderr, "[rescan] record the MCP no-scan baseline pass: %v\n", err)
		return
	}
	w.mcpNoScanHeal = nil
	if w.logger != nil {
		_ = w.logger.LogAction(string(audit.ActionUpgrade), "mcp-baselines",
			fmt.Sprintf("type=mcp migration=noscan-baseline-heal version=%s readmitted=%d (gas-ux-r2:GAP-0088)", mcpNoScanHealVersion, pass.healed))
	}
}
