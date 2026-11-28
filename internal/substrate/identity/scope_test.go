// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"
)

// B3 dc.scope: the gateway mints one token per stream; the scope round-trips
// and only stream shapes are accepted.
func TestSessionScope(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	s, err := NewSessionSigner(key, "https://defenseclaw-admin")
	if err != nil {
		t.Fatal(err)
	}
	actor := SessionActor{Atespace: "eng", Name: "web-1", UID: "0d6f8a52-4c1e-4b7e-9d0a-2f3b5c6d7e8f"}
	for _, sc := range []string{"", "port:3000", "port:65535", "mcp:github", "mcp:fs_local-2"} {
		a := actor
		a.Scope = sc
		tok, _, err := s.Issue(SessionSignIn{Person: "alice@example.test", TokenKey: "jti:scope"}, a, time.Minute)
		if err != nil {
			t.Fatalf("%q: %v", sc, err)
		}
		got, err := s.Verify(tok)
		if err != nil || got.Scope != sc || got.Actor.Scope != sc {
			t.Fatalf("%q: %+v %v", sc, got, err)
		}
	}
	for _, sc := range []string{"code", "port:", "port:0", "port:123456", "mcp:", "mcp:Up", "port:22,mcp:x", "ws"} {
		a := actor
		a.Scope = sc
		if _, _, err := s.Issue(SessionSignIn{Person: "alice@example.test", TokenKey: "jti:scope"}, a, time.Minute); err == nil {
			t.Errorf("scope %q issued", sc)
		}
	}
}
