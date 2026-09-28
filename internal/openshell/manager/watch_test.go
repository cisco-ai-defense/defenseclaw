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
	"strings"
	"testing"
	"time"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/openshell/stream"
)

// TestWatcherFollowsTheNextGatewayConnection pins that a sandbox's watcher
// ends when the connection its stream runs on is dropped (and closed) and
// follows the next connection, instead of staying on the dead one.
func TestWatcherFollowsTheNextGatewayConnection(t *testing.T) {
	e := newEnv(t, nil)
	e.run()
	sb := e.create(sandboxapi.CreateRequest{Name: "rewatch"})
	e.watch.waitStarted(t, sb.Name)
	first, err := e.m.gateway(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	next := *e.gw
	e.gw = &next
	e.m.dropGateway(first, &types.StatusError{Code: types.ErrorUnavailable, Message: "the gateway restarted"})
	e.watch.waitStarted(t, sb.Name)
	e.watch.mu.Lock()
	last := e.watch.gateways[len(e.watch.gateways)-1]
	e.watch.mu.Unlock()
	if last != &next {
		t.Fatal("the restarted watch does not run on the new connection")
	}
}

// TestDraftEventsDoNotHoldTheStream pins that a draft notification hands
// the draft poll off: a poll whose lookups hang must not hold the stream's
// receive loop, which OpenShell drops events for when it lags.
func TestDraftEventsDoNotHoldTheStream(t *testing.T) {
	savedBudget := triagePassBudget
	triagePassBudget = 2 * time.Second
	t.Cleanup(func() { triagePassBudget = savedBudget })
	e := newEnv(t, nil)
	e.run()
	sb := e.create(sandboxapi.CreateRequest{Name: "lagbox"})
	e.watch.waitStarted(t, sb.Name)
	e.dns.setHang("slow.example.org", true)
	addChunk(e, sb.Name, chunk("allow_slow_example_org_443", "slow.example.org", 443))
	h := e.watch.handler(t, sb.Name)
	for _, kind := range []stream.Kind{stream.KindDraft, stream.KindConnected} {
		done := make(chan struct{})
		go func() {
			h(stream.Event{Kind: kind, Sandbox: sb.Name})
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatalf("a %s event held the receive loop for the draft poll", kind)
		}
	}
	e.dns.setHang("slow.example.org", false)
	e.waitTriage(sb.Name)
}

// TestServerStreamWarningsAreReported pins that OpenShell's warnings on a
// sandbox's stream (dropped messages) are recorded as degraded health, and
// the watcher's own only logged.
func TestServerStreamWarningsAreReported(t *testing.T) {
	e := newEnv(t, nil)
	e.run()
	sb := e.create(sandboxapi.CreateRequest{Name: "warnbox"})
	e.watch.waitStarted(t, sb.Name)
	degraded := func() int {
		e.tel.mu.Lock()
		defer e.tel.mu.Unlock()
		n := 0
		for _, h := range e.tel.health {
			if h.Sandbox.Name == sb.Name && h.State == audit.SandboxHealthDegraded && strings.Contains(h.ErrorSummary, "lagging") {
				n++
			}
		}
		return n
	}
	e.watch.push(t, sb.Name, stream.Event{Kind: stream.KindWarning, Warning: &stream.Warning{Message: "lagging receiver: 12 messages dropped", Local: true}})
	if n := degraded(); n != 0 {
		t.Fatalf("a local warning was recorded as health: %d", n)
	}
	e.watch.push(t, sb.Name, stream.Event{Kind: stream.KindWarning, Warning: &stream.Warning{Message: "lagging receiver: 12 messages dropped"}})
	if n := degraded(); n != 1 {
		t.Fatalf("%d degraded health records for OpenShell's warning, want 1", n)
	}
}
