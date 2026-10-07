// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

type failingSetupConnector struct {
	stubConnector
	err error
}

func (c *failingSetupConnector) Setup(context.Context, connector.SetupOpts) error { return c.err }

// GAP-0132: a self-heal that keeps failing the same way (a Codex update left
// the protected executable evidence stale) is reported once, with the
// per-user pointer to doctor, not on every audit tick; a different failure
// is reported again.
func TestHookConfigGuardReportsARepeatedHealFailureOnce(t *testing.T) {
	store, logger := testStoreAndLogger(t)
	guard := NewHookConfigGuard(logger, nil, guardTestDebounce)
	conn := &failingSetupConnector{
		stubConnector: stubConnector{name: "codex"},
		err:           errors.New("selected Codex executable digest does not match protected evidence"),
	}
	opts := connector.SetupOpts{DataDir: t.TempDir()}

	degraded := func() []audit.Event {
		t.Helper()
		events, err := store.ListEvents(50)
		if err != nil {
			t.Fatalf("ListEvents: %v", err)
		}
		var out []audit.Event
		for _, ev := range events {
			if ev.Action == string(audit.ActionGuardrailDegraded) {
				out = append(out, ev)
			}
		}
		return out
	}

	for range 3 {
		if err := guard.healLocked(context.Background(), conn, opts, []string{"periodic registration audit"}, nil); err == nil {
			t.Fatal("healLocked succeeded with a failing Setup")
		}
	}
	rows := degraded()
	if len(rows) != 1 {
		t.Fatalf("guardrail-degraded rows after three identical failures = %d, want 1", len(rows))
	}
	if !strings.Contains(rows[0].Details, "defenseclaw doctor names the fix") {
		t.Fatalf("degraded row = %q, want the per-user doctor pointer", rows[0].Details)
	}

	conn.err = errors.New("a different Setup failure")
	_ = guard.healLocked(context.Background(), conn, opts, []string{"periodic registration audit"}, nil)
	if got := len(degraded()); got != 2 {
		t.Fatalf("guardrail-degraded rows after a new failure = %d, want 2", got)
	}

	guard.setHealFailure("") // the contract became current
	_ = guard.healLocked(context.Background(), conn, opts, []string{"periodic registration audit"}, nil)
	if got := len(degraded()); got != 3 {
		t.Fatalf("guardrail-degraded rows after recovery and the same failure = %d, want 3", got)
	}
}
