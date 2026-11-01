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

//go:build !windows

package manager

import (
	"strings"
	"sync/atomic"
	"testing"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/openshell/openshelltest"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// G-openshell review (rc.7, loop round 1): a create or a start checked for
// guests DefenseClaw cannot show protected once, early (legacyRunRefusal),
// and then ran its sandbox however long its providers, image and run files
// took. A security stop of another MicroVM whose sync failed contained that
// VM meanwhile, and the new sandbox ran beside it all the same. The last
// check now comes right before OpenShell's call, ordered against the
// containment (lockRun, runGate): a guest contained after the first check
// refuses the run, naming it, and the run goes ahead once its user ended it.
// The contained VM is not stopped.
func TestAGuestContainedDuringACreateOrStartRefusesIt(t *testing.T) {
	for _, run := range []struct {
		name string
		// during is a call OpenShell gets between the run's first check and
		// its gateway call.
		during string
		try    func(e *harnessEnv) error
	}{
		{"create", openshelltest.MethodCreateProvider, func(e *harnessEnv) error {
			_, err := e.tryCreate(sandboxapi.CreateRequest{Name: "beside", Copy: true, Project: e.otherProject("beside")})
			return err
		}},
		{"start", openshelltest.MethodUpdateProvider, func(e *harnessEnv) error {
			_, err := e.m.Start(e.t.Context(), "later", sandboxapi.StartRequest{})
			return err
		}},
	} {
		t.Run(run.name, func(t *testing.T) {
			e := newVMEnv(t, nil)
			e.create(sandboxapi.CreateRequest{Name: "vmbox", Copy: true})
			if run.name == "start" {
				e.create(sandboxapi.CreateRequest{Name: "later", Copy: true, Project: e.otherProject("later")})
				e.stopBox("later")
			}
			b := e.boxOf("vmbox")
			e.m.mu.Lock()
			binding := b.rec.BindingID
			e.m.mu.Unlock()
			e.fake.HandleExec(e.workloadChecks(nil, guestAnswers("exited\n", true)))
			var armed atomic.Bool
			armed.Store(true)
			e.fake.Intercept(func(method string) error {
				if method == run.during && armed.CompareAndSwap(true, false) {
					e.m.stopForAlarm("vmbox", binding, audit.SandboxFindingHookTamper)
				}
				return nil
			})
			creates, starts, stops := e.fake.Calls(openshelltest.MethodCreateSandbox), e.fake.Calls(openshelltest.MethodStartSandbox),
				e.fake.Calls(openshelltest.MethodStopSandbox)
			err := run.try(e)
			e.fake.Intercept(nil)
			if armed.Load() {
				t.Fatal("the scenario was not reached: no containment ran during the " + run.name)
			}
			e.m.mu.Lock()
			contained := b.rec.Contained
			e.m.mu.Unlock()
			if contained == "" {
				t.Fatal("the scenario was not reached: vmbox is not contained")
			}
			if apiErr := wantCode(t, err, sandboxapi.CodeConflict); !strings.Contains(apiErr.Message, "while vmbox runs ("+containedUnprotected+")") ||
				!strings.Contains(apiErr.Detail, "`defenseclaw sandbox stop vmbox`") {
				t.Fatalf("the %s beside a VM contained meanwhile = %+v", run.name, apiErr)
			}
			if n := e.fake.Calls(openshelltest.MethodCreateSandbox) - creates; n != 0 {
				t.Fatalf("%d sandboxes created beside a contained VM", n)
			}
			if n := e.fake.Calls(openshelltest.MethodStartSandbox) - starts; n != 0 {
				t.Fatalf("%d sandboxes started beside a contained VM", n)
			}
			if n := e.fake.Calls(openshelltest.MethodStopSandbox) - stops; n != 0 {
				t.Fatalf("stopped a MicroVM whose sync failed: %d stops", n)
			}
			// Its user ends it, accepting the loss: the run goes ahead.
			e.stopBoxAcceptingLoss("vmbox")
			e.fake.HandleExec(e.workloadChecks(nil, nil))
			if err := run.try(e); err != nil {
				t.Fatalf("the %s once the contained VM is stopped: %v", run.name, err)
			}
		})
	}
}

// G-openshell review (rc.7, loop round 1): under a gateway-global policy,
// the containment of a MicroVM a security stop could not sync returned at
// once, before it detached the providers whose direct network OpenShell
// composes into the sandbox's: the VM kept those routes. A global policy
// locks the sandbox's policy, not its providers: they are detached and
// confirmed detached, and the containment says it could not confirm the
// rest (the global policy's network stays open), so the VM stays named
// unprotected and refuses new runs. Once the global policy is gone, the
// reconcile withdraws its rules. The VM is not stopped.
func TestAContainmentUnderAGlobalPolicyDetachesItsProviders(t *testing.T) {
	const name = "vmglobal"
	e := newVMEnv(t, nil)
	e.create(sandboxapi.CreateRequest{Name: name, Copy: true})
	e.addNetworkRule(name, "hostport", "host.openshell.internal", 8080)
	sb, err := e.client.GetSandbox(t.Context(), name)
	must(t, err)
	if len(sb.Spec.Providers) == 0 {
		t.Fatal("the scenario was not reached: the sandbox has no provider attached")
	}
	e.fake.SetGlobalPolicy(&types.SandboxPolicy{})
	e.fake.HandleExec(e.workloadChecks(nil, guestAnswers("exited\n", true)))
	b := e.boxOf(name)
	e.m.mu.Lock()
	binding := b.rec.BindingID
	e.m.mu.Unlock()
	stops := e.fake.Calls(openshelltest.MethodStopSandbox)
	e.m.stopForAlarm(name, binding, audit.SandboxFindingHookTamper)
	if n := e.fake.Calls(openshelltest.MethodStopSandbox) - stops; n != 0 {
		t.Fatalf("stopped a MicroVM whose sync failed: %d stops", n)
	}
	sb, err = e.client.GetSandbox(t.Context(), name)
	must(t, err)
	if len(sb.Spec.Providers) != 0 {
		t.Fatalf("the contained VM keeps its providers' direct network under a global policy: %q", sb.Spec.Providers)
	}
	found := e.events(name, sandboxapi.ActivityFinding, sandboxapi.ReasonContained)
	if len(found) == 0 || !strings.Contains(found[len(found)-1].Message, "could not confirm it contained") ||
		!strings.Contains(found[len(found)-1].Message, "gateway-global policy") {
		t.Fatalf("the feed does not say the containment is unconfirmed: %+v", found)
	}
	st, err := e.m.Status(t.Context())
	must(t, err)
	if len(st.Unprotected) != 1 || st.Unprotected[0].Name != name || st.Unprotected[0].Reason != sandboxapi.UnprotectedContained {
		t.Fatalf("unprotected = %+v", st.Unprotected)
	}
	if err := e.m.legacyRunRefusal(t.Context(), ""); err == nil || !strings.Contains(err.Error(), name) {
		t.Fatalf("a new run beside it = %v", err)
	}
	e.fake.SetGlobalPolicy(nil)
	must(t, e.m.Reconcile(t.Context()))
	if e.hasRule(name, "defenseclaw_egress") || e.hasRule(name, "hostport") {
		t.Fatal("the reconcile did not withdraw its rules once the global policy was gone")
	}
	e.m.mu.Lock()
	left := b.oldSupervisorNetworkErr
	e.m.mu.Unlock()
	if left != "" {
		t.Fatalf("the withdrawal is still unconfirmed: %s", left)
	}
}

// G-openshell review (rc.7, loop round 1): a read of a guest's own gateway,
// taken while DefenseClaw was connected to another, stood for 30 s
// wherever DefenseClaw was connected. Back on its own gateway, its user
// stopped the guest; connected elsewhere again within the 30 s, the read
// named it running and refused every new run. A read its own place said
// something after (box.word) proves nothing and is read again; a place that
// does not answer leaves its last word, stopped, which releases it. None is
// stopped by DefenseClaw.
func TestAReadOlderThanTheGuestsLastWordDoesNotNameItElsewhere(t *testing.T) {
	for _, kind := range []struct {
		name  string
		guest func(t *testing.T, name string) *harnessEnv
		stop  func(e *harnessEnv, name string)
	}{
		{"a legacy docker session", func(t *testing.T, name string) *harnessEnv {
			e, _ := legacyGuest(t, name, false, nil)
			return e
		}, func(e *harnessEnv, name string) { _, err := e.m.Stop(e.t.Context(), name); must(e.t, err) }},
		{"a legacy MicroVM session", func(t *testing.T, name string) *harnessEnv {
			e, _ := legacyGuest(t, name, true, nil)
			return e
		}, func(e *harnessEnv, name string) { _, err := e.m.Stop(e.t.Context(), name); must(e.t, err) }},
		{"a contained VM", func(t *testing.T, name string) *harnessEnv {
			e := newVMEnv(t, nil)
			containedVM(t, e, name)
			return e
		}, (*harnessEnv).stopBoxAcceptingLoss},
	} {
		for _, how := range []string{"DefenseClaw's stop", "a stop there a get found"} {
			for _, homeDown := range []bool{false, true} {
				t.Run(kind.name+"/"+how+"/home down="+map[bool]string{false: "no", true: "yes"}[homeDown], func(t *testing.T) {
					const name = "staleread"
					e := kind.guest(t, name)
					own := e.gw
					var down atomic.Bool
					homeGatewayAt(e, own, &down)
					away, _ := awayGateway(e)
					switchGateway(t, e, away)
					if entry, refusal, _ := guestAccount(t, e, name); entry == nil || refusal == "" {
						t.Fatalf("the scenario was not reached: running on its own gateway, read from another: entry %+v, refusal %q", entry, refusal)
					}
					switchGateway(t, e, own)
					if how == "DefenseClaw's stop" {
						kind.stop(e, name)
					} else {
						_, err := e.client.StopSandbox(t.Context(), name)
						must(t, err)
						_, err = e.m.Get(t.Context(), name)
						must(t, err)
					}
					if entry, refusal, _ := guestAccount(t, e, name); entry != nil || refusal != "" {
						t.Fatalf("stopped on its own gateway: entry %+v, refusal %q", entry, refusal)
					}
					stops := e.fake.Calls(openshelltest.MethodStopSandbox)
					down.Store(homeDown)
					switchGateway(t, e, away)
					if entry, refusal, _ := guestAccount(t, e, name); entry != nil || refusal != "" {
						t.Fatalf("stopped on its own gateway, then on another within the read's time: entry %+v, refusal %q", entry, refusal)
					}
					if n := e.fake.Calls(openshelltest.MethodStopSandbox) - stops; n != 0 {
						t.Fatalf("%d stops", n)
					}
				})
			}
		}
	}
}
