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
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

// GAP-0608: a managed gateway that takes a call and never answers (stopped,
// hung) held the start-up confirmation of the registrations on the first
// one until revalidate gave up, and every later poll for the relay
// client's two minutes per registration. Each call now has its own
// deadline, and once one got no answer the pass asks no other registration:
// nothing is confirmed, the floor stays closed (fail closed), and the next
// pass asks again.
func TestSandboxDaemonRevalidateBoundsEachCallOnASilentGateway(t *testing.T) {
	const bound = 50 * time.Millisecond
	f := newSandboxDaemonFixture(t, func(o *SandboxDaemonOptions) { o.gatewayCallTimeout = bound })
	names := []string{"dc-a", "dc-b", "dc-c"}
	for i, name := range names {
		r := daemonRegistration{ID: fmt.Sprintf("reg-%d", i), Sandbox: name,
			Floor: config.OpenShellAdminConfig{MinProfile: "balanced"}, UpdatedAt: time.Now()}
		if err := f.d.regs.put(r); err != nil {
			t.Fatal(err)
		}
	}
	var (
		calls    atomic.Int64
		mu       sync.Mutex
		deadline []time.Duration
	)
	f.relay.currentCtx = func(ctx context.Context, _ string) (sandboxrelay.CurrentPolicy, error) {
		calls.Add(1)
		dl, ok := ctx.Deadline()
		mu.Lock()
		if ok {
			deadline = append(deadline, time.Until(dl))
		} else {
			deadline = append(deadline, -1)
		}
		mu.Unlock()
		<-ctx.Done()
		return sandboxrelay.CurrentPolicy{}, fmt.Errorf("%w: %v", sandboxrelay.ErrGatewayUnreachable, ctx.Err())
	}
	if revoked := f.d.revalidate(context.Background()); len(revoked) != 0 {
		t.Fatalf("a silent gateway revoked %+v", revoked)
	}
	if n := calls.Load(); n != 1 {
		t.Fatalf("revalidate asked a silent gateway %d times, want once (the others would wait out the same bound)", n)
	}
	mu.Lock()
	left := deadline[0]
	mu.Unlock()
	if left < 0 || left > bound {
		t.Fatalf("the confirmation call had deadline %s, want its own bound of at most %s", left, bound)
	}
	if admin := f.d.config().OpenShell.Admin; admin.MinProfile != "strict" {
		t.Fatalf("a silent gateway opened the closed floor: %+v", admin)
	}
	for _, name := range names {
		if r, _ := f.d.regs.get(name); r.Confirmed || r.Revoked {
			t.Fatalf("%s changed without an answer: %+v", name, r)
		}
	}

	// The gateway answers again: the next pass asks every registration.
	f.relay.currentCtx = nil
	f.relay.current = func(string) (sandboxrelay.CurrentPolicy, error) {
		return sandboxrelay.CurrentPolicy{V: 1, Generation: 4, Floor: &config.OpenShellAdminConfig{MinProfile: "balanced"}}, nil
	}
	f.d.revalidate(context.Background())
	for _, name := range names {
		if r, _ := f.d.regs.get(name); !r.Confirmed {
			t.Fatalf("%s not confirmed once the gateway answered", name)
		}
	}
	if admin := f.d.config().OpenShell.Admin; admin.MinProfile != "balanced" {
		t.Fatalf("floor after the gateway answered = %+v", admin)
	}
}

// The bound is the status views' own: a start-up confirmation is a view of
// the managed gateway, not a relayed hook that may wait on a judge.
func TestSandboxDaemonGatewayCallTimeoutDefault(t *testing.T) {
	if got := (&SandboxDaemon{}).gatewayCallTimeout(); got != managedViewTimeout || got > 5*time.Second {
		t.Fatalf("gateway call bound = %s, want managedViewTimeout (%s)", got, managedViewTimeout)
	}
}
