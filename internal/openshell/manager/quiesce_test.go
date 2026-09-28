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

package manager

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell/egress"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// recordingQuiescer notes which bindings a caller waited on, and how many
// profiles were imported by then.
type recordingQuiescer struct {
	mu       sync.Mutex
	waited   map[string]int
	importer *fakeImporter
}

func (q *recordingQuiescer) WaitQuiescent(_ context.Context, bindingID string, _ time.Duration) error {
	q.importer.mu.Lock()
	imported := len(q.importer.imported) + len(q.importer.updated)
	q.importer.mu.Unlock()
	q.mu.Lock()
	defer q.mu.Unlock()
	q.waited[bindingID] = imported
	return nil
}

// TestGlobalProfileImportWaitsForRunningSandboxes pins that a create that
// has to import a global provider profile (a new --credential here), which
// resets every running sandbox's connections, first tells the running
// sandboxes and waits until their hooks are quiet.
func TestGlobalProfileImportWaitsForRunningSandboxes(t *testing.T) {
	e := newEnv(t, nil)
	e.create(sandboxapi.CreateRequest{Name: "busybox"})
	running, _ := e.store.Lookup("busybox")
	q := &recordingQuiescer{waited: map[string]int{}, importer: e.importer}
	e.m.opts.Quiesce = q
	e.importer.mu.Lock()
	before := len(e.importer.imported)
	e.importer.mu.Unlock()

	e.create(sandboxapi.CreateRequest{Name: "credbox", Project: e.otherProject("cred"),
		Credentials: []sandboxapi.CredentialBinding{{Name: "STRIPE_API_KEY", Value: "stripe-secret", Host: "api.stripe.com"}}})
	e.importer.mu.Lock()
	after := len(e.importer.imported)
	e.importer.mu.Unlock()
	if after == before {
		t.Fatal("the create imported no profile")
	}
	q.mu.Lock()
	at, ok := q.waited[running.ID]
	q.mu.Unlock()
	if !ok || at != before {
		t.Fatalf("the import did not wait for the running sandbox's hooks first (waited %t, after %d of %d imports)", ok, at, after)
	}
	notified := false
	for _, ev := range e.m.ActivitySince(0, "busybox") {
		notified = notified || ev.Reason == "profile_import"
	}
	if !notified {
		t.Fatal("the running sandbox was not told about the import")
	}
}

// activityProxy is a proxy that reports per-binding tunnel activity.
type activityProxy struct {
	fakeProxy
}

func (p *activityProxy) BindingActivity(bindingID string) (int, int64) {
	if bindingID == "sb_busy" {
		return 2, 4096
	}
	return 0, 0
}

// TestApprovalBatchesWatchProxyTunnels pins that the approval batcher sees
// the attached egress proxy's per-binding traffic (triage.TunnelActivity),
// and nothing before a proxy that reports it is attached.
func TestApprovalBatchesWatchProxyTunnels(t *testing.T) {
	e := newEnv(t, nil)
	tunnels := proxyTunnels{m: e.m}
	if open, moved := tunnels.BindingActivity("sb_busy"); open != 0 || moved != 0 {
		t.Fatalf("activity without a proxy = %d, %d", open, moved)
	}
	e.m.AttachProxy(&fakeProxy{counter: egress.NewCounter(egress.CounterOptions{})})
	if open, _ := tunnels.BindingActivity("sb_busy"); open != 0 {
		t.Fatalf("activity from a proxy that reports none = %d", open)
	}
	e.m.AttachProxy(&activityProxy{fakeProxy{counter: egress.NewCounter(egress.CounterOptions{})}})
	if open, moved := tunnels.BindingActivity("sb_busy"); open != 2 || moved != 4096 {
		t.Fatalf("activity = %d, %d", open, moved)
	}
}
