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

package identity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"
)

// GAP-0744: a session token names the sign-in it was handed out for: its
// issue time when it has one, and its token key.
func TestGAP0744SessionNamesItsSignIn(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	s, err := NewSessionSigner(key, "https://gw.example")
	if err != nil {
		t.Fatal(err)
	}
	act := SessionActor{Atespace: "eng-web", Name: "alice-1", UID: "0b0e7b4c-7d8b-4c1e-9a55-0d6b9c4b1a01"}
	iat := time.Now().Add(-time.Minute).Truncate(time.Second)
	for _, in := range []SessionSignIn{
		{Person: "https://idp#alice", IssuedAt: iat, TokenKey: "jti:0123456789abcdef0123456789abcdef"},
		{Person: "kubernetes#alice", TokenKey: "tok:0123456789abcdef0123456789abcdef"},
	} {
		tok, _, err := s.Issue(in, act, 0)
		if err != nil {
			t.Fatal(err)
		}
		got, err := s.Verify(tok)
		if err != nil || got.Person != in.Person || got.SignInKey != in.TokenKey || !got.SignInIssuedAt.Equal(in.IssuedAt) {
			t.Fatalf("%+v: session %+v %v", in, got, err)
		}
	}
	if p := (Person{Issuer: "https://idp", Subject: "alice", IssuedAt: iat, TokenKey: "clm:x"}); SignInOf(p) != (SessionSignIn{Person: "https://idp#alice", IssuedAt: iat, TokenKey: "clm:x"}) {
		t.Fatalf("SignInOf %+v", SignInOf(p))
	}
}
