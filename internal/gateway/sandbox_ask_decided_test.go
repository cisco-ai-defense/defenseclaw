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

package gateway

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/sandboxreg"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

// GAP-0632: a decision on an ask (a session allow, an unblock, a user block,
// a floor refusal) is a log.sandbox.ask.decided record of the gateway that
// names the registration, the kind, the scope and the hashed person.
func TestManagedSandboxAskDecidedRecords(t *testing.T) {
	reg := managedTelemetryTestRegistration()
	for name, tc := range map[string]struct {
		req  sandboxrelay.DecisionRequest
		out  sandboxAskOutcome
		want []string
	}{
		"host port session allow": {
			req: sandboxrelay.DecisionRequest{Registration: reg.ID, Kind: sandboxrelay.DecisionEgressAllow, Host: sandboxHostAlias,
				Scope: sandboxrelay.DecisionScopeSession, ApprovalID: "ap_0e0ba4fe7acaf1f0", Port: 25432},
			want: []string{`"defenseclaw.approval.result":"approved"`, `"defenseclaw.sandbox.approval.kind":"host_port"`,
				`"defenseclaw.sandbox.approval.scope":"sandbox"`, `"defenseclaw.sandbox.decision.stored":false`, `"server.port":25432`,
				`"defenseclaw.approval.id":"ap_0e0ba4fe7acaf1f0"`},
		},
		"always unblock": {
			req: sandboxrelay.DecisionRequest{Registration: reg.ID, Kind: sandboxrelay.DecisionUnblock, Host: "example.org",
				Scope: sandboxrelay.DecisionScopeAlways},
			out: sandboxAskOutcome{Stored: true},
			want: []string{`"defenseclaw.approval.result":"approved"`, `"defenseclaw.sandbox.approval.kind":"network_rule"`,
				`"defenseclaw.sandbox.approval.scope":"always"`, `"defenseclaw.sandbox.decision.stored":true`},
		},
		"user block": {
			req: sandboxrelay.DecisionRequest{Registration: reg.ID, Kind: sandboxrelay.DecisionEgressBlock, Host: "example.org",
				Scope: sandboxrelay.DecisionScopeAlways},
			out:  sandboxAskOutcome{Stored: true},
			want: []string{`"defenseclaw.approval.result":"denied"`, `"defenseclaw.sandbox.decision.stored":true`},
		},
		"floor refusal": {
			req: sandboxrelay.DecisionRequest{Registration: reg.ID, Kind: sandboxrelay.DecisionEgressAllow, Host: "example.org",
				Scope: sandboxrelay.DecisionScopeAlways},
			out: sandboxAskOutcome{Refused: true},
			want: []string{`"defenseclaw.approval.result":"denied"`, `"defenseclaw.sandbox.managed.reason":"floor_denied"`,
				`"defenseclaw.sandbox.decision.stored":false`},
		},
	} {
		t.Run(name, func(t *testing.T) {
			capture := &rematchCapture{}
			logger := audit.NewLogger(nil)
			logger.SetRuntimeV8Emitter(capture)
			emitSandboxAskDecided(context.Background(), &APIServer{logger: logger}, reg, tc.req, tc.out)
			if capture.n != 1 {
				t.Fatalf("%d records, want 1", capture.n)
			}
			encoded, err := capture.record.MarshalJSON()
			if err != nil {
				t.Fatal(err)
			}
			s := string(encoded)
			for _, want := range append(tc.want, `sandbox.ask.decided`, `"defenseclaw.sandbox.registration.id":"`+reg.ID+`"`,
				`"defenseclaw.subject.key":"`+reg.SubjectKey+`"`) {
				if !strings.Contains(s, want) {
					t.Errorf("record lacks %s: %s", want, s)
				}
			}
		})
	}
}

// GAP-0632: POST decisions records every decision it takes or refuses, a
// session allow included (it keeps nothing, so only the record traces it).
func TestSandboxAuthorityDecisionsAreRecorded(t *testing.T) {
	f := newSandboxFixture(t, config.EnterpriseEnrollmentConfig{}, nil)
	f.setGroups(sbxAlice, "dc-sbx-contractors")
	prevCheck, prevRecord := sandboxDecisionCheck, sandboxRecordAskDecided
	sandboxDecisionCheck = func(_ config.OpenShellAdminConfig, d sandboxrelay.DecisionRequest) error {
		if d.Scope == sandboxrelay.DecisionScopeAlways {
			return &sandboxreg.DecisionRefusedError{Rule: "user_approvals", Message: "Your organization allows this only for the session."}
		}
		return nil
	}
	var mu sync.Mutex
	var got []audit.SandboxAskDecidedEvent
	sandboxRecordAskDecided = func(_ context.Context, _ *APIServer, reg sandboxreg.Registration, req sandboxrelay.DecisionRequest, out sandboxAskOutcome) {
		mu.Lock()
		defer mu.Unlock()
		got = append(got, sandboxAskDecidedEvent(reg, req, out, time.Now()))
	}
	t.Cleanup(func() { sandboxDecisionCheck, sandboxRecordAskDecided = prevCheck, prevRecord })
	resp := f.live(sbxAlice, 1)
	decide := func(kind, scope string, port int) int {
		return f.do(sbxAlice, http.MethodPost, sandboxrelay.PathDecisions, sandboxrelay.DecisionRequest{
			V: 1, Registration: resp.Registration.ID, Kind: kind, Host: sandboxHostAlias, Scope: scope, ApprovalID: "ap_0e0ba4fe7acaf1f0", Port: port,
		}, nil).Code
	}
	if code := decide(sandboxrelay.DecisionEgressAllow, sandboxrelay.DecisionScopeSession, 25432); code != http.StatusOK {
		t.Fatalf("session allow: %d", code)
	}
	if code := decide(sandboxrelay.DecisionEgressAllow, sandboxrelay.DecisionScopeAlways, 25432); code != http.StatusForbidden {
		t.Fatalf("always past the floor: %d", code)
	}
	if code := decide(sandboxrelay.DecisionEgressAllow, sandboxrelay.DecisionScopeSession, 70000); code != http.StatusBadRequest {
		t.Fatalf("an impossible port: %d", code)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 2 {
		t.Fatalf("%d decisions recorded, want 2 (the invalid one is none): %+v", len(got), got)
	}
	session, refused := got[0], got[1]
	if session.Result != audit.SandboxApprovalApproved || session.Scope != audit.SandboxApprovalScopeSandbox || session.Kind != audit.SandboxApprovalHostPort ||
		session.Port != 25432 || session.ApprovalID != "ap_0e0ba4fe7acaf1f0" || session.Stored == nil || *session.Stored ||
		session.Sandbox.Managed.RegistrationID != resp.Registration.ID || session.Sandbox.Managed.SubjectKey == "" {
		t.Errorf("session allow record = %+v", session)
	}
	if refused.Result != audit.SandboxApprovalDenied || refused.Reason != sandboxAskReasonFloorDenied || refused.Scope != "" {
		t.Errorf("floor refusal record = %+v", refused)
	}
}

// GAP-0659: the approval id comes from the caller, so it never decides
// whether a decision is recorded. The route refuses an id the record can't
// carry, and a record of one is made without it.
func TestSandboxAskDecidedDoesNotDependOnTheApprovalID(t *testing.T) {
	reg := managedTelemetryTestRegistration()
	capture := &rematchCapture{}
	logger := audit.NewLogger(nil)
	logger.SetRuntimeV8Emitter(capture)
	emitSandboxAskDecided(context.Background(), &APIServer{logger: logger}, reg, sandboxrelay.DecisionRequest{
		Registration: reg.ID, Kind: sandboxrelay.DecisionEgressAllow, Host: "example.org", Scope: sandboxrelay.DecisionScopeSession,
		ApprovalID: "bad id",
	}, sandboxAskOutcome{})
	if capture.n != 1 {
		t.Fatalf("%d records of a decision with an unusable approval id, want 1", capture.n)
	}
	if encoded, _ := capture.record.MarshalJSON(); strings.Contains(string(encoded), "bad id") {
		t.Fatalf("the record carries the unusable id: %s", encoded)
	}

	f := newSandboxFixture(t, config.EnterpriseEnrollmentConfig{}, nil)
	f.setGroups(sbxAlice, "dc-sbx-contractors")
	prevRecord := sandboxRecordAskDecided
	var mu sync.Mutex
	recorded := 0
	sandboxRecordAskDecided = func(context.Context, *APIServer, sandboxreg.Registration, sandboxrelay.DecisionRequest, sandboxAskOutcome) {
		mu.Lock()
		recorded++
		mu.Unlock()
	}
	t.Cleanup(func() { sandboxRecordAskDecided = prevRecord })
	resp := f.live(sbxAlice, 1)
	for _, id := range []string{"bad id", "ap_x;rm", "-ap"} {
		if code := f.do(sbxAlice, http.MethodPost, sandboxrelay.PathDecisions, sandboxrelay.DecisionRequest{
			V: 1, Registration: resp.Registration.ID, Kind: sandboxrelay.DecisionEgressAllow, Host: "example.org",
			Scope: sandboxrelay.DecisionScopeSession, ApprovalID: id,
		}, nil).Code; code != http.StatusBadRequest {
			t.Fatalf("approval id %q: %d, want 400", id, code)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if recorded != 0 {
		t.Fatalf("%d refused requests recorded as decisions", recorded)
	}
}

// GAP-0148: a refused resolution is a mandatory failed policy.resolved
// record of the caller with the refusal's reason, for a policy refusal
// and for a forged pack alike, while an accepted one stays the plain
// record.
func TestSandboxAuthorityRefusedResolutionIsRecorded(t *testing.T) {
	capture := &rematchCapture{}
	logger := audit.NewLogger(nil)
	logger.SetRuntimeV8Emitter(capture)
	attempt := managedTelemetryTestRegistration()
	attempt.ID, attempt.SandboxName, attempt.SandboxID, attempt.BindingID = "", "", "", ""
	emitSandboxPolicyResolveRefused(&APIServer{logger: logger}, attempt, sandboxrelay.ReasonNotAllowed)
	if capture.n != 1 {
		t.Fatalf("%d records of a refused resolution, want 1", capture.n)
	}
	encoded, err := capture.record.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"sandbox.policy.resolved", `"` + sandboxrelay.ReasonNotAllowed + `"`, `"defenseclaw.subject.key":"` + attempt.SubjectKey + `"`} {
		if !strings.Contains(string(encoded), want) {
			t.Errorf("record lacks %s: %s", want, encoded)
		}
	}

	f := newSandboxFixture(t, config.EnterpriseEnrollmentConfig{}, nil)
	f.setGroups(sbxAlice, "dc-sbx-contractors")
	prev := sandboxRecordResolveRefused
	var mu sync.Mutex
	var got []string
	sandboxRecordResolveRefused = func(_ *APIServer, attempt sandboxreg.Registration, reason string) {
		mu.Lock()
		defer mu.Unlock()
		got = append(got, attempt.Profile+":"+reason+":"+strconv.FormatBool(attempt.SubjectKey != "" && attempt.UID == sbxAlice.UID))
	}
	t.Cleanup(func() { sandboxRecordResolveRefused = prev })
	resolve := func(req sandboxrelay.ResolveRequest) int {
		return f.do(sbxAlice, http.MethodPost, sandboxrelay.PathPolicyResolve, req, map[string]string{sandboxrelay.ConnectorHeader: req.Connector}).Code
	}
	if code := resolve(claudeResolve()); code != http.StatusOK {
		t.Fatalf("own resolve: %d", code)
	}
	f.cfg.OpenShell.Admin.AllowedHarnesses = []string{"codex"}
	if code := resolve(claudeResolve()); code == http.StatusOK {
		t.Fatal("resolve of an agent the floor does not allow was accepted")
	}
	f.cfg.OpenShell.Admin.AllowedHarnesses = nil
	no := false
	f.cfg.OpenShell.Admin.Allowed = &no
	if code := resolve(claudeResolve()); code == http.StatusOK {
		t.Fatal("resolve with sandboxes disallowed was accepted")
	}
	mu.Lock()
	defer mu.Unlock()
	want := []string{"contractors:" + sandboxrelay.ReasonNotAllowed + ":true", "contractors:" + sandboxrelay.ReasonNotAllowed + ":true"}
	if strings.Join(got, ";") != strings.Join(want, ";") {
		t.Fatalf("refused resolutions recorded = %q, want %q", got, want)
	}
}
