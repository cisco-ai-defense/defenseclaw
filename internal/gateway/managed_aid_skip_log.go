// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"sync"
	"time"
)

// managed_aid_skip_log.go centralises the operator-visible warning
// emitted whenever an inspection in managed_enterprise mode ends
// WITHOUT a Cisco AI Defense verdict. In managed_enterprise the
// AID cloud lane is the sole enforcement source of truth (local
// detectors are demoted at sidecar.runGuardrail / demoteLocalBlock
// ForManaged), so any inspection that returns without a cloud
// verdict is a fail-open — the current prompt or tool call is
// allowed through with no cloud adjudication. The old code paths
// recorded this via metrics only; there was no live signal in
// gateway.err.log, so operators tailing the log during triage saw
// nothing. This file's rate-limited stderr emitter is what closes
// that gap.
//
// The mandate is strict: no managed_enterprise inspection may skip
// AID silently. Every choke point that can produce a "no cisco
// verdict" outcome — inspectManagedAIDOnly's fail-open branch,
// mergeVerdict's managed-mode cisco==nil path, the AID inspect
// client's own return-nil branches — routes through
// logManagedAIDSkip so the condition surfaces uniformly.

// managedAIDSkipCooldown throttles the operator-visible line per
// (reason) so a persistently broken box does not flood the log.
// Once per minute per reason is enough to make the skip visible in
// a live tail without drowning the rest of the log.
const managedAIDSkipCooldown = 60 * time.Second

// managedAIDSkipState is the process-wide rate-limit clock for
// logManagedAIDSkip. Keyed by reason string so distinct causes each
// keep their own cooldown — a persistent "no-content" skip does not
// suppress the first "cloud-token-unavailable" skip.
var managedAIDSkipState = struct {
	mu   sync.Mutex
	last map[string]time.Time
}{
	last: make(map[string]time.Time),
}

// logManagedAIDSkip emits a rate-limited operator-visible stderr
// warning naming the specific reason a managed_enterprise inspection
// ended without a Cisco AI Defense verdict. Safe to call from any
// goroutine.
//
// reason is a short label — e.g. "cloud-token-unavailable",
// "hook-inspector-nil", "proxy-cisco-nil", "aid-http-no-verdict",
// "no-content" — chosen so operators tailing gateway.err.log can
// tell WHY the fail-open happened without cross-referencing the
// structured event stream. detail is optional additional context
// (typically an underlying error message); pass "" when nothing
// specific to add.
func logManagedAIDSkip(reason, detail string) {
	if reason == "" {
		reason = "unspecified"
	}
	now := time.Now()
	managedAIDSkipState.mu.Lock()
	last := managedAIDSkipState.last[reason]
	if now.Sub(last) < managedAIDSkipCooldown {
		managedAIDSkipState.mu.Unlock()
		return
	}
	managedAIDSkipState.last[reason] = now
	managedAIDSkipState.mu.Unlock()
	if detail == "" {
		fmt.Fprintf(defaultLogWriter,
			"  [cisco-ai-defense] WARNING: managed_enterprise AID inspection SKIPPED (reason=%s) — enforcement is fail-open for this call\n",
			reason)
		return
	}
	fmt.Fprintf(defaultLogWriter,
		"  [cisco-ai-defense] WARNING: managed_enterprise AID inspection SKIPPED (reason=%s: %s) — enforcement is fail-open for this call\n",
		reason, detail)
}
