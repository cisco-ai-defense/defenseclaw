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
	"context"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

// es-demo:GAP-0012, rel-1-0-2:GAP-0172: a running managed sandbox took the
// administrator's new policy 20-50 s after the ensure reported it applied.
// A relayed answer's other generation now polls every live registration at
// once, for a tightened and a loosened policy alike. The generation is a
// digest of the caller's own policy, compared for equality only: the
// loosened policy's is smaller than the tightened one's, and ordered as a
// counter it was ignored until the next minute's poll.
func TestSandboxDaemonNewGenerationAppliesTheLiveFieldsAtOnce(t *testing.T) {
	f := newSandboxDaemonFixture(t) // policy poll and checks: once an hour
	if err := f.d.regs.put(daemonRegistration{ID: "reg-1", Sandbox: "dc-a", Digest: "sha256:v1", UpdatedAt: time.Now(), Confirmed: true}); err != nil {
		t.Fatal(err)
	}
	live := sandboxrelay.LiveFields{EgressBlock: []string{"github.com"}}
	f.relay.current = func(string) (sandboxrelay.CurrentPolicy, error) {
		return sandboxrelay.CurrentPolicy{V: 1, Generation: 9, Digest: "sha256:v2", Live: live}, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = f.d.superviseLoop(ctx, make(chan error))
	}()
	defer func() {
		cancel()
		<-done
	}()
	wait := func(digest string, block []string) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if r, _ := f.d.regs.get("dc-a"); r.Digest == digest && len(r.Floor.EgressBlock) == len(block) {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		r, _ := f.d.regs.get("dc-a")
		t.Fatalf("the live fields did not follow generation change: %+v", r)
	}
	// Tightened: github.com blocked.
	f.d.observeGeneration("reg-1", 9)
	wait("sha256:v2", live.EgressBlock)
	// Loosened again, under a smaller generation digest.
	f.relay.current = func(string) (sandboxrelay.CurrentPolicy, error) {
		return sandboxrelay.CurrentPolicy{V: 1, Generation: 4, Digest: "sha256:v3"}, nil
	}
	f.d.observeGeneration("reg-1", 4)
	wait("sha256:v3", nil)
	if r, _ := f.d.regs.get("dc-a"); r.Generation != 4 {
		t.Fatalf("registration generation = %d, want 4", r.Generation)
	}
	// Another registration's generation, or the one applied, asks nothing.
	f.relay.current = func(string) (sandboxrelay.CurrentPolicy, error) {
		t.Error("polled for a generation the registration already has")
		return sandboxrelay.CurrentPolicy{}, nil
	}
	f.d.observeGeneration("reg-1", 4)
	f.d.observeGeneration("reg-unknown", 77)
	time.Sleep(200 * time.Millisecond)
}
