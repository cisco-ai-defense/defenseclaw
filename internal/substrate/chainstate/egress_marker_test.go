// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package chainstate

import (
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

// The callout's verdict refuses a secret read, resolved or joined only
// through the file-unknown marker (1.0.10 lead ruling 2026-11-14), from the
// window and from a prepared step alike; the opt-in alert never refuses.
func TestEgressVerdictFileUnknownMarker(t *testing.T) {
	index, _ := guardrail.ToolChainIndexByID(guardrail.ToolChainSecretReadThenEgress)
	step1, _ := guardrail.ToolChainStepMask(guardrail.ToolChainSecretReadThenEgress, 1)
	now := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	read := func(digest string) guardrail.ToolChainProjection {
		p := guardrail.ToolChainProjection{ParseStatus: actionfacts.StatusPartial, DetectionStepMask: step1}
		p.EnforcementJoinDigests[index] = digest
		return p
	}
	const exact = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	marker := guardrail.ToolChainFileUnknownDigest
	event := func(id string, seq uint64, p guardrail.ToolChainProjection) guardrail.ToolChainWindowEvent {
		return guardrail.ToolChainWindowEvent{SemanticEventID: id, Sequence: seq, ReceivedAt: now.Add(-time.Minute), Projection: p}
	}
	pending := func(p guardrail.ToolChainProjection) audit.ToolChainPendingStep {
		return audit.ToolChainPendingStep{PreparedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), Projection: p}
	}
	for _, row := range []struct {
		name       string
		w          memoWindow
		action     string
		wantDeny   bool
		wantReason string
	}{
		{"window: resolved read", memoWindow{Next: 2, Events: []guardrail.ToolChainWindowEvent{event("r1", 1, read(exact))}}, EgressBlock, true, "blocks"},
		{"window: marker-only read", memoWindow{Next: 2, Events: []guardrail.ToolChainWindowEvent{event("r1", 1, read(marker))}}, EgressBlock, true, "blocks"},
		{"window: marker read and a resolved read", memoWindow{Next: 3, Events: []guardrail.ToolChainWindowEvent{event("r1", 1, read(marker)), event("r2", 2, read(exact))}}, EgressBlock, true, "blocks"},
		{"pending: resolved read", memoWindow{Next: 1, Pending: []audit.ToolChainPendingStep{pending(read(exact))}}, EgressBlock, true, "blocks"},
		{"pending: marker-only read", memoWindow{Next: 1, Pending: []audit.ToolChainPendingStep{pending(read(marker))}}, EgressBlock, true, "blocks"},
		{"window marker, pending resolved", memoWindow{Next: 2, Events: []guardrail.ToolChainWindowEvent{event("r1", 1, read(marker))}, Pending: []audit.ToolChainPendingStep{pending(read(exact))}}, EgressBlock, true, "blocks"},
		{"opt-in alert: marker-only read", memoWindow{Next: 2, Events: []guardrail.ToolChainWindowEvent{event("r1", 1, read(marker))}}, EgressAlert, false, "alerts"},
		{"opt-in alert: resolved read", memoWindow{Next: 2, Events: []guardrail.ToolChainWindowEvent{event("r1", 1, read(exact))}}, EgressAlert, false, "alerts"},
	} {
		var m egressMemo
		m.set(row.w)
		v, ok := m.verdict(now, row.action)
		if !ok {
			t.Fatalf("%s: no verdict", row.name)
		}
		if v.Rule != guardrail.ToolChainSecretReadThenEgress || v.Deny != row.wantDeny {
			t.Errorf("%s: %+v, want deny=%v for %s", row.name, v, row.wantDeny, guardrail.ToolChainSecretReadThenEgress)
		}
		if !strings.Contains(v.Reason, row.wantReason) {
			t.Errorf("%s: reason %q, want it to say %q", row.name, v.Reason, row.wantReason)
		}
	}
}
