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
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	"github.com/defenseclaw/defenseclaw/internal/sandboxreg"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

func managedTelemetryTestRegistration() sandboxreg.Registration {
	return sandboxreg.Registration{
		V: 1, ID: "reg-abcdefghijklmnopqrstuvwxyz", UID: 1001, UserName: "ent-alice@dclab.test",
		SubjectKey: "hmac-sha256:" + strings.Repeat("a", 64),
		Profile:    "contractors", ProfileMatch: "group", MatchedGroup: "dc-sbx-contractors@dclab.test",
		ProfileDigest: "sha256:" + strings.Repeat("b", 64), EffectiveDigest: "sha256:" + strings.Repeat("c", 64),
		Generation: 42, Connector: "claudecode", Harness: "claudecode", WorkdirMode: "copy", Driver: "docker",
		OpenShell: "0.1.3", InstallMode: "setup", SandboxID: "sb-1", SandboxName: "proj-ab12", BindingID: "bind-1",
		State: sandboxreg.StateLive, CreatedAt: time.Now().UTC(),
	}
}

// The managed gateway's stamps fit the registry, so the strict managed
// record families accept every record the gateway and the daemon produce
// (a refused stamp would lose the record).
func TestManagedSandboxStampsFitTheRegistry(t *testing.T) {
	reg := managedTelemetryTestRegistration()
	identity := sandboxRecordIdentity(reg)
	if identity.Managed.ProfileMatch != "group" || identity.Managed.InstallMode != "setup" ||
		identity.Managed.Provisional == nil || identity.Managed.PolicyGeneration != 42 || identity.Driver != "docker" {
		t.Fatalf("identity = %+v", identity)
	}
	none := reg
	none.ProfileMatch, none.InstallMode, none.Driver = "none", "bundled", "podman-ish"
	if got := sandboxRecordIdentity(none); got.Managed.ProfileMatch != "" || got.Managed.InstallMode != "" || got.Driver != "" {
		t.Fatalf("unregistered descriptive stamps kept: %+v", got)
	}
	for action, want := range map[string]string{"stopped": audit.SandboxManagedStop, "removed": audit.SandboxManagedRemove, "alerted": audit.SandboxManagedAlert, "": audit.SandboxManagedAlert} {
		if got := sandboxManagedAction(action); got != want {
			t.Errorf("action %q = %q, want %q", action, got, want)
		}
	}
}

// GAP-0470: in prerequisite mode the registration carried the configured
// OpenShell range (">=0.1.1 <0.2.0") as its version, the strict managed
// families refused the stamp, and no re-match (or resolve) was recorded.
// The range is left out and the record is made.
func TestManagedSandboxRematchRecordedUnderAVersionRange(t *testing.T) {
	capture := &rematchCapture{}
	logger := audit.NewLogger(nil)
	logger.SetRuntimeV8Emitter(capture)
	a := &APIServer{logger: logger}
	before := managedTelemetryTestRegistration()
	before.OpenShell, before.InstallMode, before.Profile = ">=0.1.1 <0.2.0", "prerequisite", "engineering"
	after := before
	after.Profile, after.Generation = "contractors", before.Generation+1
	if got := sandboxRecordIdentity(after).Managed.OpenShellVersion; got != "" {
		t.Fatalf("OpenShell version stamp = %q, want none for a range", got)
	}
	emitSandboxPolicyRematched(a, before, after)
	if capture.n != 1 {
		t.Fatalf("%d log.sandbox.policy.rematched records under a version range, want 1", capture.n)
	}
	encoded, err := capture.record.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if s := string(encoded); !strings.Contains(s, `"defenseclaw.sandbox.policy.previous_profile":"engineering"`) ||
		!strings.Contains(s, `"defenseclaw.guardrail.profile.name":"contractors"`) {
		t.Fatalf("record = %s", s)
	}
}

// A run refused because another account uses the sandboxes is recorded as an
// unavailable sandbox with the reason account_busy, stamped with the caller's
// own subject key, and names no other account (GAP-0598).
func TestManagedSandboxAccountBusyRefusalIsRecorded(t *testing.T) {
	capture := &rematchCapture{}
	logger := audit.NewLogger(nil)
	logger.SetRuntimeV8Emitter(capture)
	a := &APIServer{logger: logger}
	reg := sandboxreg.Registration{UID: 1001, UserName: "ent-carol", SubjectKey: "hmac-sha256:" + strings.Repeat("a", 64)}
	for _, harnessName := range []string{"claudecode", ""} {
		capture.n = 0
		payload, _ := json.Marshal(map[string]string{"harness": harnessName})
		emitSandboxDaemonEvent(context.Background(), a, reg, sandboxrelay.Event{Kind: sandboxrelay.EventAccountBusy, Time: time.Now(), Payload: payload})
		if capture.n != 1 {
			t.Fatalf("harness %q: %d account-busy records, want 1", harnessName, capture.n)
		}
		encoded, err := capture.record.MarshalJSON()
		if err != nil {
			t.Fatal(err)
		}
		s := string(encoded)
		for _, want := range []string{`"defenseclaw.sandbox.managed.reason":"account_busy"`, "host_run_unavailable",
			`"defenseclaw.subject.key":"` + reg.SubjectKey + `"`} {
			if !strings.Contains(s, want) {
				t.Errorf("harness %q: record lacks %s: %s", harnessName, want, s)
			}
		}
	}
}

// GAP-0677: the daemon's foreign-container event names the container's
// image, and the record the gateway makes of it keeps it, so the alert says
// which image runs the agent.
func TestManagedSandboxForeignContainerRecordsTheImage(t *testing.T) {
	capture := &rematchCapture{}
	logger := audit.NewLogger(nil)
	logger.SetRuntimeV8Emitter(capture)
	a := &APIServer{logger: logger}
	reg := sandboxreg.Registration{UID: 1001, UserName: "ent-carol", SubjectKey: "hmac-sha256:" + strings.Repeat("a", 64)}
	payload, _ := json.Marshal(map[string]string{
		"container_id": "7296e42c596a", "image": "cxr4-plain-nolabel:lab", "name": "cxr4plain3", "harness": "claudecode",
	})
	emitSandboxDaemonEvent(context.Background(), a, reg, sandboxrelay.Event{Kind: sandboxrelay.EventForeignContainer, Time: time.Now(), Payload: payload})
	if capture.n != 1 {
		t.Fatalf("%d foreign-container records, want 1", capture.n)
	}
	encoded, err := capture.record.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if s := string(encoded); !strings.Contains(s, `"defenseclaw.sandbox.container.image":"cxr4-plain-nolabel:lab"`) ||
		!strings.Contains(s, `"defenseclaw.sandbox.name":"cxr4plain3"`) {
		t.Fatalf("record = %s", s)
	}
}

// rematchCapture counts the records it is given.
type rematchCapture struct {
	sandboxStampCapture
	n int
}

func (capture *rematchCapture) EmitRuntimeV8(
	ctx context.Context, meta router.Metadata, build audit.RuntimeV8Builder,
) (audit.RuntimeV8EmitOutcome, error) {
	capture.n++
	return capture.sandboxStampCapture.EmitRuntimeV8(ctx, meta, build)
}

// A payload that is not JSON, or an event kind the route does not take, is
// dropped without panicking and without a recorder.
func TestManagedSandboxDaemonEventPayloads(t *testing.T) {
	a := &APIServer{}
	reg := managedTelemetryTestRegistration()
	payload, _ := json.Marshal(map[string]any{"sandbox": "raw-1", "rules": []string{"r1", "r2"}, "action": "removed"})
	for _, ev := range []sandboxrelay.Event{
		{Kind: sandboxrelay.EventForeignRule, Time: time.Now(), Payload: payload},
		{Kind: sandboxrelay.EventForeignSandbox, Time: time.Now(), Payload: payload},
		{Kind: sandboxrelay.EventForeignContainer, Time: time.Now(), Payload: payload},
		{Kind: sandboxrelay.EventSettingsDrift, Time: time.Now(), Payload: json.RawMessage(`{"field":"version"}`)},
		{Kind: sandboxrelay.EventAccessRefused, Time: time.Now(), Payload: json.RawMessage(`{"host":"example.com","port":443}`)},
		{Kind: sandboxrelay.EventForeignRule, Time: time.Now(), Payload: json.RawMessage(`not json`)},
	} {
		emitSandboxDaemonEvent(context.Background(), a, reg, ev)
	}
	emitSandboxPolicyResolved(a, reg)
	emitSandboxPolicyRematched(a, reg, reg)
	emitRequireSandboxRecord(context.Background(), a, requireSandboxRecord{Connector: "claudecode", Reason: requireSandboxReasonRequired})
	emitRequireSandboxRecord(context.Background(), nil, requireSandboxRecord{Connector: "claudecode", Reason: requireSandboxReasonRequired})
}
