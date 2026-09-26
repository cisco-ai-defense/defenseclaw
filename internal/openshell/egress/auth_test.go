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
	"encoding/base64"
	"errors"
	"fmt"
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
	if err != nil {
		t.Fatal(err)
	}
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
	if err != nil {
		t.Fatal(err)
	}
	pass, _ := u.User.Password()
	if u.Scheme != "http" || u.Host != "host.openshell.internal:18972" || u.User.Username() != a.Username || pass != a.Password {
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
	if err := s.Register(c1, p1); err != nil {
		t.Fatal(err)
	}
	if got, ok := s.Authenticate(c1.Username, c1.Password); !ok || got != p1 {
		t.Fatalf("Authenticate = %+v, %v", got, ok)
	}
	if _, ok := s.Authenticate(c1.Username, c1.Password+"x"); ok {
		t.Error("wrong password accepted")
	}
	if _, ok := s.Authenticate("dcx-unknown", c1.Password); ok {
		t.Error("unknown username accepted")
	}
	if got, ok := s.Lookup("b-1"); !ok || got != p1 {
		t.Errorf("Lookup = %+v, %v", got, ok)
	}

	// Re-registering the same credential updates the principal.
	p1.Mode = ModeOpen
	if err := s.Register(c1, p1); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Authenticate(c1.Username, c1.Password); got.Mode != ModeOpen {
		t.Errorf("principal not updated: %+v", got)
	}

	// Registering a new credential for the binding rotates the old one out.
	c2, _ := NewCredential()
	if err := s.Register(c2, p1); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Authenticate(c1.Username, c1.Password); ok {
		t.Error("rotated credential still works")
	}
	if _, ok := s.Authenticate(c2.Username, c2.Password); !ok {
		t.Error("new credential rejected")
	}
	if s.Len() != 1 {
		t.Errorf("Len = %d, want 1", s.Len())
	}

	// A username belongs to one binding.
	if err := s.Register(c2, Principal{BindingID: "b-2"}); !errors.Is(err, ErrCredentialInUse) {
		t.Errorf("username reuse = %v", err)
	}

	if !s.Revoke("b-1") || s.Revoke("b-1") {
		t.Error("Revoke did not revoke exactly once")
	}
	if _, ok := s.Authenticate(c2.Username, c2.Password); ok {
		t.Error("revoked credential still works")
	}
	if _, ok := s.Lookup("b-1"); ok {
		t.Error("revoked binding still listed")
	}

	invalid := []struct {
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
	}
	for _, tt := range invalid {
		if err := s.Register(tt.c, tt.p); !errors.Is(err, ErrInvalidCredential) {
			t.Errorf("%s: Register = %v, want ErrInvalidCredential", tt.name, err)
		}
	}
}
