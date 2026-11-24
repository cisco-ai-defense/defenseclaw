// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/sandboxreg"
)

// substrate-1 GAP-0486: the audit row of the first hook call after a resume
// says so; other rows do not. A call served after the suspend but before its
// record arrived was the first one, so no later call is marked; and the
// marks stay bounded.
func TestGAP0486ResumeMarks(t *testing.T) {
	key, err := sandboxreg.SubstrateKey("eng-web", subUID2)
	if err != nil {
		t.Fatal(err)
	}
	ctx := withSubstrateActor(context.Background(), verifiedSubstrateActor("eng-web", "bob-1", subUID2, "actor/eng-web/bob-1", key))
	if _, ok := substrateHookAuditExtra(ctx)["substrate_first_hook_after_resume"]; ok {
		t.Fatal("an ordinary hook row is marked")
	}
	if got := substrateHookAuditExtra(withFirstHookAfterResume(ctx))["substrate_first_hook_after_resume"]; got != "true" {
		t.Fatalf("the first hook row after a resume carries %q", got)
	}

	var m substrateResumeMarks
	t0 := time.Now()
	m.suspendedAt("u1", t0)
	if m.hook("u1", t0) || !m.hook("u1", t0.Add(time.Second)) || m.hook("u1", t0.Add(2*time.Second)) {
		t.Fatal("want exactly the first call that started after the suspend marked")
	}
	// The record arrives after the first call was served: no later mark.
	m.hook("u2", t0.Add(3*time.Second))
	m.suspendedAt("u2", t0.Add(2*time.Second))
	if m.hook("u2", t0.Add(4*time.Second)) {
		t.Fatal("a later call was marked as the first after the resume")
	}
	// A deleted actor is forgotten; the memory is bounded.
	m.suspendedAt("u3", t0)
	m.forget("u3")
	if m.hook("u3", t0.Add(time.Second)) {
		t.Fatal("a deleted actor kept its mark")
	}
	for i := range maxSubstrateResumeActors + 10 {
		m.hook(fmt.Sprintf("a%d", i), t0.Add(time.Duration(i)))
	}
	if n := len(m.lastHook); n > maxSubstrateResumeActors {
		t.Fatalf("the marks remember %d actors, bound %d", n, maxSubstrateResumeActors)
	}
}
