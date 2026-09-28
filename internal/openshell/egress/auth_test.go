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

package egress

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

func TestParseProxyAuthorization(t *testing.T) {
	enc := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	tests := []struct {
		name       string
		values     []string
		user, pass string
		ok         bool
	}{
		{"basic", []string{"Basic " + enc("dcx-1:secret")}, "dcx-1", "secret", true},
		{"scheme case", []string{"bAsIc " + enc("u:p")}, "u", "p", true},
		{"colon in password", []string{"Basic " + enc("u:p:q")}, "u", "p:q", true},
		{"empty password", []string{"Basic " + enc("u:")}, "u", "", true},
		{"extra spaces", []string{"  Basic   " + enc("u:p") + "  "}, "u", "p", true},
		{"missing", nil, "", "", false},
		{"two headers", []string{"Basic " + enc("u:p"), "Basic " + enc("v:q")}, "", "", false},
		{"bearer", []string{"Bearer " + enc("u:p")}, "", "", false},
		{"no blob", []string{"Basic"}, "", "", false},
		{"blank blob", []string{"Basic    "}, "", "", false},
		{"bad base64", []string{"Basic !!!"}, "", "", false},
		{"no colon", []string{"Basic " + enc("user")}, "", "", false},
		{"empty user", []string{"Basic " + enc(":p")}, "", "", false},
		{"oversized", []string{"Basic " + enc("u:"+strings.Repeat("x", 600))}, "", "", false},
	}
	for _, tt := range tests {
		user, pass, ok := parseProxyAuthorization(tt.values)
		if ok != tt.ok || user != tt.user || pass != tt.pass {
			t.Errorf("%s: got %q %q %v, want %q %q %v", tt.name, user, pass, ok, tt.user, tt.pass, tt.ok)
		}
	}
}

func TestNewCredential(t *testing.T) {
	a, err := NewCredential()
	must(t, err)
	b, _ := NewCredential()
	if a == b || a.Password == b.Password {
		t.Fatal("NewCredential repeated itself")
	}
	if !regexp.MustCompile(`^dcx-[0-9a-f]{16}$`).MatchString(a.Username) || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(a.Password) {
		t.Fatalf("credential format = %q / %d chars", a.Username, len(a.Password))
	}
	if err := validateCredential(a); err != nil {
		t.Fatalf("minted credential fails validation: %v", err)
	}

	raw := a.ProxyURL("host.openshell.internal", 18972)
	u, err := url.Parse(raw)
	must(t, err)
	if pass, _ := u.User.Password(); u.Scheme != "http" || u.Host != "host.openshell.internal:18972" || u.User.Username() != a.Username || pass != a.Password {
		t.Errorf("ProxyURL = %q", raw)
	}
	for _, s := range []string{a.String(), fmt.Sprintf("%v", a), fmt.Sprintf("%+v", a), fmt.Sprintf("%#v", a)} {
		if strings.Contains(s, a.Password) {
			t.Errorf("formatted credential leaks the password: %q", s)
		}
	}
}

func TestCredentialStore(t *testing.T) {
	s := NewCredentialStore()
	c1, _ := NewCredential()
	p1 := Principal{BindingID: "b-1", SandboxID: "sb-1", Mode: ModeAllowlist}
	must(t, s.Register(c1, p1))
	if got, ok := s.Authenticate(c1.Username, c1.Password); !ok || got != p1 {
		t.Fatalf("Authenticate = %+v, %v", got, ok)
	}
	if got, ok := s.Lookup("b-1"); !ok || got != p1 {
		t.Errorf("Lookup = %+v, %v", got, ok)
	}
	for _, bad := range [][2]string{{c1.Username, c1.Password + "x"}, {"dcx-unknown", c1.Password}} {
		if _, ok := s.Authenticate(bad[0], bad[1]); ok {
			t.Errorf("Authenticate(%q, ...) accepted a wrong password or an unknown username", bad[0])
		}
	}

	// Re-registering the same credential updates the principal.
	p1.Mode = ModeOpen
	must(t, s.Register(c1, p1))
	if got, _ := s.Authenticate(c1.Username, c1.Password); got.Mode != ModeOpen {
		t.Errorf("principal not updated: %+v", got)
	}

	// Registering a new credential for the binding rotates the old one out.
	c2, _ := NewCredential()
	must(t, s.Register(c2, p1))
	_, oldOK := s.Authenticate(c1.Username, c1.Password)
	_, newOK := s.Authenticate(c2.Username, c2.Password)
	if oldOK || !newOK || s.Len() != 1 {
		t.Errorf("after rotation: old credential %v, new %v, Len %d", oldOK, newOK, s.Len())
	}

	// A username belongs to one binding.
	if err := s.Register(c2, Principal{BindingID: "b-2"}); !errors.Is(err, ErrCredentialInUse) {
		t.Errorf("username reuse = %v", err)
	}

	if !s.Revoke("b-1") || s.Revoke("b-1") {
		t.Error("Revoke did not revoke exactly once")
	}
	_, authOK := s.Authenticate(c2.Username, c2.Password)
	if _, listed := s.Lookup("b-1"); authOK || listed {
		t.Error("a revoked credential still works or is still listed")
	}

	for _, tt := range []struct {
		name string
		c    Credential
		p    Principal
	}{
		{"empty username", Credential{Password: c1.Password}, p1},
		{"colon username", Credential{Username: "a:b", Password: c1.Password}, p1},
		{"long username", Credential{Username: strings.Repeat("a", 65), Password: c1.Password}, p1},
		{"short password", Credential{Username: "u", Password: "short"}, p1},
		{"space in password", Credential{Username: "u", Password: strings.Repeat("a", 16) + " "}, p1},
		{"no binding", c1, Principal{}},
		{"bad mode", c1, Principal{BindingID: "b-9", Mode: "deny"}},
	} {
		if err := s.Register(tt.c, tt.p); !errors.Is(err, ErrInvalidCredential) {
			t.Errorf("%s: Register = %v, want ErrInvalidCredential", tt.name, err)
		}
	}
}

var testEgressOff = Decision{Category: CategoryEgressOff, Source: SourceAdmin,
	Reason: "your organization's required sandbox pack (strict) turns web egress off for this sandbox (openshell.admin.required_pack)"}

// A sandbox whose policy turned its egress off while it ran was told its
// proxy credentials were wrong (a 407), and the agent went debugging them.
// A suspended credential is refused with a 403 that carries the reason,
// for CONNECT, forwarded requests and the tunnels already open. A
// suspension needs a reason to give, and Register or Revoke ends it.
func TestSuspendedCredentialIsRefusedWithTheReason(t *testing.T) {
	h := newHarness(t, nil)
	h.dialer.route(443, startEcho(t))
	conn, br := h.openTunnel(h.cred, "example.com:443", "")

	if err := h.creds.Suspend(h.cred, h.pr, Decision{Category: CategoryEgressOff}); !errors.Is(err, ErrInvalidCredential) {
		t.Fatalf("Suspend without a reason = %v", err)
	}
	must(t, h.creds.Suspend(h.cred, h.pr, testEgressOff))
	_, authOK := h.creds.Authenticate(h.cred.Username, h.cred.Password)
	_, listed := h.creds.Lookup(h.pr.BindingID)
	_, _, wrongOK := h.creds.Suspended(h.cred.Username, "wrong-password-0123456789")
	if authOK || listed || wrongOK {
		t.Fatalf("a suspended credential authenticates (%v), has a principal (%v) or matches a wrong secret (%v)", authOK, listed, wrongOK)
	}
	if got, dec, ok := h.creds.Suspended(h.cred.Username, h.cred.Password); !ok || got.BindingID != h.pr.BindingID || dec.Allowed || dec.Reason != testEgressOff.Reason {
		t.Fatalf("Suspended = %+v %+v %v", got, dec, ok)
	}
	// The open tunnel ends with the refusal, reported as a block.
	if n := h.proxy.Recheck(h.pr.BindingID); n != 1 {
		t.Fatalf("Recheck ended %d tunnels, want 1", n)
	}
	waitClosed(t, "suspended credential", conn, br)
	if blocked := h.sink.ofKind(EventBlocked); len(blocked) != 1 || blocked[0].Category != CategoryEgressOff {
		t.Fatalf("blocked events = %+v", blocked)
	}

	resp, body := h.refused(h.cred, "example.com:443")
	if resp.status != http.StatusForbidden || body.Category != CategoryEgressOff || body.Host != "example.com" || body.Port != 443 ||
		!strings.Contains(body.Message, "required sandbox pack (strict)") || !strings.Contains(body.HowToUnblock, "credentials are fine") ||
		body.Unblockable {
		t.Fatalf("CONNECT = %d %+v", resp.status, body)
	}
	if got := h.sink.ofKind(EventAuthFailed); len(got) != 0 {
		t.Fatalf("a suspension counted as a failed authentication: %+v", got)
	}
	if res, data := fetch(t, h.clientFor(h.cred, nil), "http://example.com/"); res.StatusCode != http.StatusForbidden || !strings.Contains(string(data), "egress_off") {
		t.Fatalf("forwarded GET = %d %s", res.StatusCode, data)
	}

	// Registering it again lifts the suspension; revoking drops it too.
	must(t, h.creds.Register(h.cred, h.pr))
	if again, againBr := h.openTunnel(h.cred, "example.com:443", ""); !relays(again, againBr) {
		t.Fatal("no tunnel after the suspension was lifted")
	}
	must(t, h.creds.Suspend(h.cred, h.pr, testEgressOff))
	if !h.creds.Revoke(h.pr.BindingID) {
		t.Fatal("Revoke dropped nothing")
	}
	if _, _, ok := h.creds.Suspended(h.cred.Username, h.cred.Password); ok {
		t.Fatal("a revoked credential is still suspended")
	}
}
