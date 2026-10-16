// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
)

// #1241: metric.defenseclaw.sandbox.active was exported only when a phase
// changed, so a sandbox that ran quietly for 15 minutes read as none on the
// Sandboxes board once Prometheus marked the last point stale. The recorder
// exports every connector's count again on each RecordActiveSandboxes (the
// gateway calls it every minute), a stopped connector's as 0, and
// RecordActiveSandboxesIfDue at most once per interval.
func TestSandboxActiveGaugeIsExportedAgainWhileNothingChanges(t *testing.T) {
	_, runtime, recorder := newSandboxTestRecorder(t, router.AdmissionOrdinary)
	ctx := context.Background()
	active := func() []int64 {
		t.Helper()
		var out []int64
		for _, metric := range sandboxMetrics(t, runtime, observability.TelemetryInstrumentDefenseClawSandboxActive) {
			out = append(out, sandboxMetricValue(t, metric))
		}
		return out
	}
	// Nothing tracked yet: nothing to export.
	if err := recorder.RecordActiveSandboxes(ctx); err != nil || len(active()) != 0 {
		t.Fatalf("before any sandbox: %v %v", err, active())
	}
	ready := SandboxLifecycleEvent{Sandbox: SandboxIdentity{Name: "dc-claudecode-long-0001", Connector: "claudecode", Phase: SandboxPhaseReady}}
	if err := recorder.RecordSandboxLifecycle(ctx, ready); err != nil {
		t.Fatal(err)
	}
	if got := active(); len(got) != 1 || got[0] != 1 {
		t.Fatalf("after ready: %v", got)
	}
	// A quiet sandbox: the next intervals export it again.
	for range 2 {
		if err := recorder.RecordActiveSandboxes(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if got := active(); len(got) != 3 || got[1] != 1 || got[2] != 1 {
		t.Fatalf("while it runs: %v", got)
	}
	// Due at most once per interval.
	if err := recorder.RecordActiveSandboxesIfDue(ctx, time.Hour); err != nil || len(active()) != 3 {
		t.Fatalf("not due: %v %v", err, active())
	}
	if err := recorder.RecordActiveSandboxesIfDue(ctx, 0); err != nil || len(active()) != 4 {
		t.Fatalf("due: %v %v", err, active())
	}
	// Stopped: 0, and 0 again on the next interval, not a stale 1.
	stopped := ready
	stopped.Sandbox.Phase = SandboxPhaseStopped
	if err := recorder.RecordSandboxLifecycle(ctx, stopped); err != nil {
		t.Fatal(err)
	}
	if err := recorder.RecordActiveSandboxes(ctx); err != nil {
		t.Fatal(err)
	}
	if got := active(); len(got) != 6 || got[4] != 0 || got[5] != 0 {
		t.Fatalf("after the stop: %v", got)
	}
	// A recorder without its runtime fails, so the caller logs it.
	if err := (&SandboxRecorder{}).RecordActiveSandboxes(ctx); err == nil {
		t.Fatal("a recorder without a logger exported")
	}
}
