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

package egress

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

var testEgressOff = Decision{Category: CategoryEgressOff, Source: SourceAdmin,
	Reason: "your organization's required sandbox pack (strict) turns web egress off for this sandbox (openshell.admin.required_pack)"}

// A sandbox whose policy turned its egress off while it ran was told its
// proxy credentials were wrong (a 407), and the agent went debugging them.
// A suspended credential is refused with a 403 that carries the reason,
// for CONNECT, forwarded requests and the tunnels already open.
func TestSuspendedCredentialIsRefusedWithTheReason(t *testing.T) {
	h := newHarness(t, nil)
	h.dialer.route(443, startEcho(t))
	conn, br := h.openTunnel(h.cred, "example.com:443", "")

	if err := h.creds.Suspend(h.cred, h.pr, testEgressOff); err != nil {
		t.Fatal(err)
	}
	if _, ok := h.creds.Authenticate(h.cred.Username, h.cred.Password); ok {
		t.Fatal("a suspended credential authenticates")
	}
	if _, ok := h.creds.Lookup(h.pr.BindingID); ok {
		t.Fatal("a suspended credential has a principal")
	}
	if pr, _, ok := h.creds.Suspended(h.cred.Username, "wrong-password-0123456789"); ok {
		t.Fatalf("a wrong secret matched the suspension: %+v", pr)
	}
	// The open tunnel ends with the refusal, reported as a block.
	if n := h.proxy.Recheck(h.pr.BindingID); n != 1 {
		t.Fatalf("Recheck ended %d tunnels, want 1", n)
	}
	waitClosed(t, "suspended credential", conn, br)
	if blocked := h.sink.ofKind(EventBlocked); len(blocked) != 1 || blocked[0].Category != CategoryEgressOff {
		t.Fatalf("blocked events = %+v", blocked)
	}

	_, _, resp := h.connect("example.com:443", basicAuth(h.cred), nil)
	var body BlockResponse
	if err := json.Unmarshal(resp.body, &body); err != nil {
		t.Fatalf("body %q: %v", resp.body, err)
	}
	if resp.status != http.StatusForbidden || body.Category != CategoryEgressOff || body.Host != "example.com" || body.Port != 443 ||
		!strings.Contains(body.Message, "required sandbox pack (strict)") || !strings.Contains(body.HowToUnblock, "credentials are fine") ||
		body.Unblockable {
		t.Fatalf("CONNECT = %d %+v", resp.status, body)
	}
	if got := h.sink.ofKind(EventAuthFailed); len(got) != 0 {
		t.Fatalf("a suspension counted as a failed authentication: %+v", got)
	}

	res, err := h.clientFor(h.cred, nil).Get("http://example.com/")
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusForbidden || !strings.Contains(string(data), "egress_off") {
		t.Fatalf("forwarded GET = %d %s", res.StatusCode, data)
	}

	// Registering it again lifts the suspension.
	if err := h.creds.Register(h.cred, h.pr); err != nil {
		t.Fatal(err)
	}
	if _, ok := h.creds.Authenticate(h.cred.Username, h.cred.Password); !ok {
		t.Fatal("the credential does not authenticate after Register")
	}
	again, againBr := h.openTunnel(h.cred, "example.com:443", "")
	if !relays(again, againBr) {
		t.Fatal("no tunnel after the suspension was lifted")
	}
}

// A suspension needs a reason to give.
func TestSuspendNeedsAReason(t *testing.T) {
	s := NewCredentialStore()
	c, err := NewCredential()
	if err != nil {
		t.Fatal(err)
	}
	pr := Principal{BindingID: "b1"}
	if err := s.Suspend(c, pr, Decision{Category: CategoryEgressOff}); !errors.Is(err, ErrInvalidCredential) {
		t.Fatalf("Suspend without a reason = %v", err)
	}
	if err := s.Suspend(c, pr, testEgressOff); err != nil {
		t.Fatal(err)
	}
	if got, dec, ok := s.Suspended(c.Username, c.Password); !ok || got.BindingID != "b1" || dec.Allowed || dec.Reason != testEgressOff.Reason {
		t.Fatalf("Suspended = %+v %+v %v", got, dec, ok)
	}
	if !s.Revoke("b1") {
		t.Fatal("Revoke dropped nothing")
	}
	if _, _, ok := s.Suspended(c.Username, c.Password); ok {
		t.Fatal("a revoked credential is still suspended")
	}
}
