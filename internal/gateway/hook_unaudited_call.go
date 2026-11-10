// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
)

// hookAuditGapCategory marks a hook-failures.jsonl line the gateway wrote
// itself for a tool call it answered but could not write the audit row of.
const hookAuditGapCategory = "audit"

// auditGap reports a line the gateway wrote for a call it answered without
// being able to record it. The call was checked, so it is no gateway outage.
func (l hookFailureLine) auditGap() bool {
	return strings.TrimSpace(l.Category) == hookAuditGapCategory
}

// recordUnauditedHookCall keeps the record of a script-route tool call whose
// audit row could not be written (a locked or full store, a write that ran
// past its window). The gateway has answered the call and no hook line exists
// for it, since the hook got an ordinary answer, so before this the allowed
// call had neither a row nor a line anywhere (GAP-1031, the per-user Windows
// flood). The gateway appends the same line a hook would to the data
// directory's hook-failures.jsonl, which sits outside the store: the failure
// report writes the call's decision row from it once the store takes writes
// again, by tool id, once. Only a per-user gateway reads that log; a managed
// gateway records a shed or abandoned call at admission instead. Best effort:
// a log that cannot be written leaves the stderr line of the failed audit
// write as the only trace.
func (a *APIServer) recordUnauditedHookCall(connectorName string, req agentHookRequest, resp agentHookResponse) {
	if a == nil || !hookFailOpenReportApplies(a.scannerCfg) || a.scannerCfg.SecureClientIntegration() ||
		req.ToolInvocationID == "" || !hookexec.ToolGateEvent(connectorName, req.HookEventName) {
		return
	}
	outcome, mode := "fail_open", "open"
	if resp.Action == "block" {
		outcome, mode = "fail_closed", "closed"
	}
	line, err := json.Marshal(struct {
		TS        string `json:"ts"`
		Connector string `json:"connector"`
		Hook      string `json:"hook"`
		Event     string `json:"event"`
		SessionID string `json:"session_id"`
		CallID    string `json:"call_id"`
		ToolID    string `json:"tool_id"`
		Reason    string `json:"reason"`
		Category  string `json:"category"`
		FailMode  string `json:"fail_mode"`
		Outcome   string `json:"outcome"`
	}{
		TS: time.Now().UTC().Format(time.RFC3339), Connector: connectorName, Hook: "defenseclaw-gateway",
		Event: req.HookEventName, SessionID: req.SessionID, CallID: req.ToolInvocationID, ToolID: req.ToolInvocationID,
		Reason: "the gateway could not write this call's audit record", Category: hookAuditGapCategory,
		FailMode: mode, Outcome: outcome,
	})
	if err != nil {
		return
	}
	dir := filepath.Join(a.scannerCfg.DataDir, "logs")
	if err := os.Mkdir(dir, 0o700); err != nil && !os.IsExist(err) {
		fmt.Fprintf(os.Stderr, "[gateway] unaudited hook call not kept connector=%s: %v\n", connectorName, err)
		return
	}
	file, err := os.OpenFile(filepath.Join(dir, hookFailuresFile), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[gateway] unaudited hook call not kept connector=%s: %v\n", connectorName, err)
		return
	}
	defer file.Close()
	if _, err := file.Write(append(line, '\n')); err != nil {
		fmt.Fprintf(os.Stderr, "[gateway] unaudited hook call not kept connector=%s: %v\n", connectorName, err)
	}
}
