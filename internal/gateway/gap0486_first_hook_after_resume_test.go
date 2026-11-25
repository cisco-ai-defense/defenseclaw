// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"net/http"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/chainstate"
	"github.com/defenseclaw/defenseclaw/internal/substrate/telemetryrelay"
)

// substrate-1 GAP-0486: once the controller saw an actor suspended (the
// lifecycle record the leader relays), the actor's first hook call after
// that is its first one after the resume, and the gateway records
// defenseclaw.substrate.first_hook_after_resume for it, once. Calls before
// the suspend, and the calls after the first, record none; a suspend and a
// resume the controller saw inside one pass record none either (the first
// call may have run before that pass). Before the fix no component recorded
// it (the docs said so).
func TestGAP0486FirstHookAfterResumeIsRecordedOnce(t *testing.T) {
	runtime, capture := newProxyGeneratedMetricRuntime(t)
	relayStore, relayClient := substrateRelayLeader(t)
	f := newSubstrateFixture(t, func(sc *SubstrateConfig) { sc.Relay = &telemetryrelay.Taker{Leader: relayClient} })
	f.api.bindObservabilityV8Runtimes(runtime, nil, nil, runtime)
	relay := func(recs ...telemetryrelay.Record) {
		t.Helper()
		relayStore.Add(recs...)
		// Two relay passes: the leader hands the suspended set out, and
		// this replica acknowledges it (GAP-0486).
		gap0486Take(t, f)
		gap0486Take(t, f)
	}
	lifecycle := func(event string, at time.Time) telemetryrelay.Record {
		return telemetryrelay.Record{Kind: telemetryrelay.KindLifecycle, Lifecycle: event, At: at,
			Atespace: "eng-web", Actor: "alice-1", UID: subUID1, Connector: "claudecode"}
	}
	hook := func(session string) {
		t.Helper()
		rec := f.do(t, f.actor, http.MethodPost, "/api/v1/substrate/hook/claudecode", "tok-alice",
			envelope("claudecode", map[string]any{"hook_event_name": "UserPromptSubmit", "prompt": "list the files", "session_id": session, "cwd": "/work/app"}))
		if rec.Code != http.StatusOK {
			t.Fatalf("hook %d %s", rec.Code, rec.Body)
		}
	}
	count := func() (first, rtt int) {
		for _, m := range capture.metricSnapshot() {
			switch m.Descriptor().Name {
			case "defenseclaw.substrate.first_hook_after_resume":
				first++
			case "defenseclaw.substrate.hook_rtt":
				rtt++
			}
		}
		return first, rtt
	}

	hook("r1") // before any suspend
	relay(lifecycle(chainstate.LifecycleSuspended, time.Now()))
	time.Sleep(5 * time.Millisecond)
	relay(lifecycle(chainstate.LifecycleResumed, time.Now()))
	hook("r1") // the first call after the resume
	hook("r1")
	if first, rtt := count(); first != 1 || rtt != 3 {
		t.Fatalf("after a suspend and a resume: first_hook_after_resume recorded %d times, hook_rtt %d; want 1 and 3", first, rtt)
	}

	// A suspend and a resume inside one controller pass: no mark.
	at := time.Now()
	relay(lifecycle(chainstate.LifecycleSuspended, at), lifecycle(chainstate.LifecycleResumed, at))
	hook("r1")
	if first, _ := count(); first != 1 {
		t.Fatalf("a suspend and resume inside one pass recorded first_hook_after_resume (%d in all)", first)
	}
}
