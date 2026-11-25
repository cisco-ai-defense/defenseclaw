// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/sandboxreg"
)

// substrate-1 GAP-0486: the audit row of the first hook call after a resume
// says so; other rows do not, nor does one whose claim the leader refused
// or that is still unanswered. Which call is the first is the leader's
// decision (telemetryrelay TestGAP0486Leader*).
func TestGAP0486ResumeMarks(t *testing.T) {
	key, err := sandboxreg.SubstrateKey("eng-web", subUID2)
	if err != nil {
		t.Fatal(err)
	}
	ctx := withSubstrateActor(context.Background(), verifiedSubstrateActor("eng-web", "bob-1", subUID2, "actor/eng-web/bob-1", key))
	if _, ok := substrateHookAuditExtra(ctx)["substrate_first_hook_after_resume"]; ok {
		t.Fatal("an ordinary hook row is marked")
	}
	if got := substrateHookAuditExtra(withFirstHookAfterResume(ctx, gap0486Claimed(true)))["substrate_first_hook_after_resume"]; got != "true" {
		t.Fatalf("the first hook row after a resume carries %q", got)
	}
	if _, ok := substrateHookAuditExtra(withFirstHookAfterResume(ctx, gap0486Claimed(false)))["substrate_first_hook_after_resume"]; ok {
		t.Fatal("a refused claim marked the row")
	}
	pending := &substrateResumeClaim{done: make(chan struct{})}
	t0 := time.Now()
	if pending.isFirst() || time.Since(t0) > 5*resumeClaimWait {
		t.Fatalf("an unanswered claim marked the row, or waited %v (bound %v)", time.Since(t0), resumeClaimWait)
	}
	pending.ok = true
	close(pending.done)
	if pending.isFirst() {
		t.Fatal("a claim answered after the row was written changed the answer")
	}
}

func gap0486Claimed(first bool) *substrateResumeClaim {
	c := &substrateResumeClaim{done: make(chan struct{}), ok: first}
	close(c.done)
	return c

}
