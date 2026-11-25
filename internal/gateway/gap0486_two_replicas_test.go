// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/chainstate"
	"github.com/defenseclaw/defenseclaw/internal/substrate/leader"
	"github.com/defenseclaw/defenseclaw/internal/substrate/telemetryrelay"
)

func newGAP0486Replica(t *testing.T, client *leader.Client) (*substrateFixture, func() int) {
	t.Helper()
	runtime, capture := newProxyGeneratedMetricRuntime(t)
	f := newSubstrateFixture(t, func(sc *SubstrateConfig) { sc.Relay = &telemetryrelay.Taker{Leader: client} })
	f.api.bindObservabilityV8Runtimes(runtime, nil, nil, runtime)
	return f, func() int {
		n := 0
		for _, m := range capture.metricSnapshot() {
			if m.Descriptor().Name == "defenseclaw.substrate.first_hook_after_resume" {
				n++
			}
		}
		return n
	}
}

func gap0486Take(t *testing.T, f *substrateFixture) {
	t.Helper()
	tk := f.api.substrateState().cfg.Relay
	tk.Record = f.api.recordSubstrateRelay
	if err := tk.TakeOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func gap0486Hook(t *testing.T, f *substrateFixture) {
	t.Helper()
	rec := f.do(t, f.actor, http.MethodPost, "/api/v1/substrate/hook/claudecode", "tok-alice",
		envelope("claudecode", map[string]any{"hook_event_name": "UserPromptSubmit", "prompt": "list the files", "session_id": "r2", "cwd": "/work/app"}))
	if rec.Code != http.StatusOK {
		t.Fatalf("hook %d %s", rec.Code, rec.Body)
	}
}

// substrate-1 GAP-0486 (RV-T6A): with two gateway replicas (the chart
// default), only one replica takes the suspend record from the leader's
// queue, and the actor's next call may land on the other one. The true
// first hook call after the resume is marked wherever it lands, and no later
// call is. Before the fix the mark was per replica: the first call, on the
// replica that did not take the record, was not marked, and the second, on
// the one that did, was.
func TestGAP0486TwoReplicasMarkOnlyTheTrueFirstCall(t *testing.T) {
	relayStore, client := substrateRelayLeader(t)
	a, firstsA := newGAP0486Replica(t, client)
	b, firstsB := newGAP0486Replica(t, client)
	gap0486Hook(t, a)
	gap0486Hook(t, b)
	gap0486Take(t, a)
	gap0486Take(t, b)

	relayStore.Add(telemetryrelay.Record{Kind: telemetryrelay.KindLifecycle, Lifecycle: chainstate.LifecycleSuspended, At: time.Now(),
		Atespace: "eng-web", Actor: "alice-1", UID: subUID1, Connector: "claudecode"})
	// A takes the record; both replicas then run a few relay passes.
	for range 2 {
		gap0486Take(t, a)
		gap0486Take(t, b)
	}
	time.Sleep(5 * time.Millisecond)

	gap0486Hook(t, b) // the true first call after the resume, on B
	gap0486Hook(t, a) // the second, on A
	gap0486Hook(t, b)
	if fa, fb := firstsA(), firstsB(); fa != 0 || fb != 1 {
		t.Fatalf("first_hook_after_resume: replica A (took the record) %d, replica B (served the first call) %d; want 0 and 1", fa, fb)
	}
}
