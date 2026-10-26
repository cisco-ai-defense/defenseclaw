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

package gateway

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// heldStopFleet is a fleet over fixed phases whose Stop is held as the
// manager's user stop is when a MicroVM's disk sync fails (GAP-1163), and
// whose StopForPolicy stops.
type heldStopFleet struct {
	fakeSandboxFleet
	held int
}

func (f *heldStopFleet) Stop(_ context.Context, name string) (*sandboxapi.Sandbox, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.held++
	return nil, sandboxapi.Errorf(sandboxapi.CodeConflict, "sandbox %s keeps running: DefenseClaw could not sync its MicroVM's disk", name)
}

func (f *heldStopFleet) StopForPolicy(ctx context.Context, name string) (*sandboxapi.Sandbox, error) {
	return f.fakeSandboxFleet.Stop(ctx, name)
}

// The listener-loss containment is DefenseClaw's own security stop (another
// program may receive the sandbox's hooks and credentials): the runtime of
// the OSS sidecar and of the managed daemon contains through the manager's
// policy stop, so a MicroVM whose sync fails is stopped in one pass, not
// held on every pass while the foreign listener keeps its traffic.
func TestListenerLossStopsThroughThePolicyStop(t *testing.T) {
	f := newSandboxRuntimeFixture(t, false)
	if pf, ok := f.rt.fleet.(policyFleet); !ok || pf.policyStopper != policyStopper(f.rt.manager) {
		t.Fatalf("the containment fleet is %T, not the manager's policy stop", f.rt.fleet)
	}
	fleet := &heldStopFleet{fakeSandboxFleet: fakeSandboxFleet{phases: map[string]string{"vm": "ready", "off": "stopped"}}}
	var feed syncRecorder[sandboxapi.ActivityEvent]
	stopSandboxesWithoutListener(t.Context(), policyFleet{fleet}, feed.add, "egress", map[string]bool{})
	if got := fleet.stops(); !slices.Equal(got, []string{"vm"}) || fleet.held != 0 {
		t.Fatalf("policy stops %v, held user stops %d; want one policy stop of vm", got, fleet.held)
	}
	for _, ev := range feed.snapshot() {
		if strings.Contains(ev.Message, "could not stop it") {
			t.Fatalf("the containment said it could not stop: %+v", ev)
		}
	}
}

// stopCtxController records whether each stop accepts an unsynced stop.
type stopCtxController struct {
	*fakeSandboxController
	accepted []bool
}

func (c *stopCtxController) Stop(ctx context.Context, name string) (*sandboxapi.Sandbox, error) {
	c.accepted = append(c.accepted, sandboxapi.UnsyncedStopAccepted(ctx))
	return c.fakeSandboxController.Stop(ctx, name)
}

// `sandbox stop --yes` reaches the manager as a stop that accepts the
// loss of a failed MicroVM sync; an empty stop body does not.
func TestSandboxStopBodyCarriesTheAcceptedLoss(t *testing.T) {
	ctl := &stopCtxController{fakeSandboxController: &fakeSandboxController{}}
	_, h := sandboxTestAPI(t, ctl, true)
	for _, body := range []string{"", `{}`, `{"accept_unsynced":true}`} {
		if w := serve(h, sandboxRequest(http.MethodPost, sandboxapi.PathSandboxes+"/box/stop", body)); w.Code != http.StatusOK {
			t.Fatalf("stop %q = %d %s", body, w.Code, w.Body.String())
		}
	}
	if !slices.Equal(ctl.accepted, []bool{false, false, true}) {
		t.Fatalf("accepted = %v", ctl.accepted)
	}
}
