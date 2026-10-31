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

//go:build linux || darwin

package gateway

import (
	"net/http"
	"testing"
)

// #1241 (rel-1-0-2:GAP-0176): a managed gateway that starts again has a new
// recorder that tracks no sandbox, and a sandbox that runs on quietly sends
// no lifecycle record to count it by: the Sandboxes board showed no active
// sandbox until its next phase change. Its daemon's next poll counts it
// again from the registration, a stopped report takes it back, and a
// lifecycle record decides once one comes.
func TestManagedSandboxActiveCountsARunningSandboxAfterARestart(t *testing.T) {
	f, _ := managedTelemetryFixture(t)
	id := boundRegistration(t, f, sbxAlice, 1)
	if rec := postEvents(f, sbxAlice, id, phaseClaim(t, "dc-claude-1", "ready")); rec.Code != http.StatusAccepted {
		t.Fatalf("ready: %d %s", rec.Code, rec.Body.String())
	}
	if got := f.api.managedSandboxRecorder().ActiveSandboxes("claudecode"); got != 1 {
		t.Fatalf("before the restart: %d active, want 1", got)
	}

	restarted := newSandboxFixtureOn(t, f)
	_, logger := testStoreAndLogger(t)
	restarted.api.logger = logger
	t.Cleanup(func() { managedSandboxRecorders.Delete(restarted.api) })
	recorder := restarted.api.managedSandboxRecorder()
	if recorder.TrackedSandboxes() != 0 {
		t.Fatal("a new gateway's recorder tracks a sandbox")
	}
	active := func(when string, want int64) {
		t.Helper()
		if got := recorder.ActiveSandboxes("claudecode"); got != want {
			t.Fatalf("%s: %d active, want %d", when, got, want)
		}
	}
	report := func(running bool) {
		t.Helper()
		if code, _ := restarted.report(sbxAlice, id, running); code != http.StatusOK {
			t.Fatalf("state report running=%v: %d", running, code)
		}
	}
	report(true)
	active("the daemon's first poll after the restart", 1)
	report(false)
	active("a stopped report", 0)
	// A start runs it under a new registration (GAP-0673).
	id = restartedRegistration(t, restarted, sbxAlice, id)
	report(true)
	active("running again", 1)
	if code, _ := restarted.current(sbxAlice, id); code != http.StatusOK {
		t.Fatalf("policy/current: %d", code)
	}
	active("a policy/current poll", 1)
	if rec := postEvents(restarted, sbxAlice, id, phaseClaim(t, "dc-claude-1", "stopped")); rec.Code != http.StatusAccepted {
		t.Fatalf("stopped: %d %s", rec.Code, rec.Body.String())
	}
	report(true)
	active("a running report after the lifecycle record's stop", 0)
}
