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
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

type fakeDecisionsRelay struct {
	err  error
	sent []sandboxrelay.DecisionRequest
}

func (f *fakeDecisionsRelay) Decide(_ context.Context, req sandboxrelay.DecisionRequest) (sandboxrelay.DecisionResult, error) {
	f.sent = append(f.sent, req)
	if f.err != nil {
		return sandboxrelay.DecisionResult{}, f.err
	}
	return sandboxrelay.DecisionResult{V: 1, Stored: req.Scope == sandboxrelay.DecisionScopeAlways,
		Decision: sandboxrelay.Decision{ID: "d1", Registration: req.Registration, Kind: req.Kind, Host: req.Host, Scope: req.Scope}}, nil
}

func (f *fakeDecisionsRelay) Decisions(context.Context, string) ([]sandboxrelay.Decision, error) {
	return nil, f.err
}

func (f *fakeDecisionsRelay) Events(context.Context, sandboxrelay.EventBatch) error { return f.err }

// The managed daemon's persister hands decisions to the managed gateway
// and turns its answers into the errors the CLI shows: a refusal past the
// floor is the organization's, with the gateway's own text; a gone
// registration asks for a new sandbox; a busy or unreachable gateway
// fails the decision closed; the config.yaml persistence is never used.
func TestSandboxDecisionsClient(t *testing.T) {
	relay := &fakeDecisionsRelay{}
	c := newSandboxDecisionsClient(relay, func(sandbox string) (string, bool) { return "reg-" + sandbox, sandbox == "mine" })
	if r, ok := c.SandboxRegistration("mine"); !ok || r != "reg-mine" {
		t.Fatalf("SandboxRegistration(mine) = %q, %v", r, ok)
	}
	if _, ok := c.SandboxRegistration("other"); ok {
		t.Fatal("SandboxRegistration named a registration the daemon does not hold")
	}
	if _, ok := newSandboxDecisionsClient(relay, nil).SandboxRegistration("mine"); ok {
		t.Fatal("a client without the daemon's registrations named one")
	}
	res, err := c.Decide(t.Context(), sandboxrelay.DecisionRequest{Registration: "reg-a", Kind: sandboxrelay.DecisionEgressAllow,
		Host: "api.example.org", Scope: sandboxrelay.DecisionScopeAlways})
	if err != nil || !res.Stored || len(relay.sent) != 1 || relay.sent[0].V != sandboxrelay.WireVersion {
		t.Fatalf("decide = %+v, %v (sent %+v)", res, err, relay.sent)
	}
	refusal := "blocked by your organization's DefenseClaw policy: your profile lets you approve access for this session only. Request access: it-security@example.com"
	for _, tc := range []struct {
		err  error
		code string
		text string
	}{
		{&sandboxrelay.Error{Status: http.StatusForbidden, Reason: sandboxrelay.ReasonDecisionRefused, Message: refusal}, sandboxapi.CodeAdminViolation, "it-security@example.com"},
		{&sandboxrelay.Error{Status: http.StatusGone, Reason: sandboxrelay.ReasonRegistrationRevoked}, sandboxapi.CodeConflict, "start it again"},
		{&sandboxrelay.Error{Status: http.StatusNotFound, Reason: sandboxrelay.ReasonRegistrationUnknown}, sandboxapi.CodeConflict, "start it again"},
		{&sandboxrelay.Error{Status: http.StatusTooManyRequests, Reason: "enterprise_managed_rate_limited", RetryAfter: "2"}, sandboxapi.CodeUnavailable, "retry after 2s"},
		{fmt.Errorf("dial: %w", sandboxrelay.ErrGatewayUnreachable), sandboxapi.CodeUnavailable, "can't be reached"},
		{sandboxrelay.ErrSocketUntrusted, sandboxapi.CodeUnavailable, "can't be reached"},
		// Other 403s are the gateway's refusals, never the floor's.
		{&sandboxrelay.Error{Status: http.StatusForbidden, Reason: "csrf_header_missing"}, sandboxapi.CodeUpstream, "refused the request"},
		{&sandboxrelay.Error{Status: http.StatusForbidden, Reason: "enterprise_managed_root_denied"}, sandboxapi.CodeUpstream, "refused the request"},
		{&sandboxrelay.Error{Status: http.StatusForbidden, Reason: sandboxrelay.ReasonConnectorMismatch}, sandboxapi.CodeUpstream, "refused the request"},
		{&sandboxrelay.Error{Status: http.StatusForbidden, Reason: sandboxrelay.ReasonNotAllowed}, sandboxapi.CodeUpstream, "refused the request"},
	} {
		relay.err = tc.err
		_, err := c.Decide(t.Context(), sandboxrelay.DecisionRequest{Registration: "reg-a", Kind: sandboxrelay.DecisionUnblock,
			Host: "api.example.org", Scope: sandboxrelay.DecisionScopeSession})
		if !sandboxapi.IsCode(err, tc.code) || !strings.Contains(err.Error(), tc.text) {
			t.Errorf("%v -> %v, want %s naming %q", tc.err, err, tc.code, tc.text)
		}
	}
	if err := c.AllowAlways(t.Context(), "api.example.org"); !sandboxapi.IsCode(err, sandboxapi.CodeInvalid) {
		t.Fatalf("AllowAlways = %v; the managed daemon has no configuration to write", err)
	}
	if err := c.BlockAlways(t.Context(), "api.example.org"); !sandboxapi.IsCode(err, sandboxapi.CodeInvalid) {
		t.Fatalf("BlockAlways = %v", err)
	}
}
