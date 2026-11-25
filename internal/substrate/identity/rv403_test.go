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

// RV4-03: Issue refuses a sign-in with no key, so it never mints a session
// that relay verify would take for one a 1.0.10 gateway minted and not
// check against its sign-in.
func TestRV403IssueRefusesASignInWithNoKey(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	s, err := NewSessionSigner(key, "https://gw.example")
	if err != nil {
		t.Fatal(err)
	}
	act := SessionActor{Atespace: "eng-web", Name: "alice-1", UID: "0b0e7b4c-7d8b-4c1e-9a55-0d6b9c4b1a01"}
	iat := time.Now().Add(-time.Minute).Truncate(time.Second)
	for _, in := range []SessionSignIn{
		{Person: "https://idp#alice"},
		{Person: "https://idp#alice", IssuedAt: iat},
		{Person: "https://idp#alice", IssuedAt: iat, TokenKey: " \t"},
	} {
		if tok, _, err := s.Issue(in, act, 0); err == nil {
			t.Errorf("%+v: Issue signed a session with no sign-in key: %.40s...", in, tok)
		}
	}
	if _, _, err := s.Issue(SessionSignIn{Person: "https://idp#alice", IssuedAt: iat, TokenKey: "jti:a"}, act, 0); err != nil {
		t.Fatalf("a keyed sign-in: %v", err)
	}
}
