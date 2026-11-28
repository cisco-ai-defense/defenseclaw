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

package relay

import (
	"testing"
	"time"
)

// GAP-0569: the actor relay accepted a session token for 60 s after its exp
// (the skew applied to exp). It now refuses a token from the second it
// expires; the skew stays on nbf, for a gateway whose clock runs ahead of
// the actor's.
func TestRelayRefusesASessionTokenTheSecondItExpiresGAP0569(t *testing.T) {
	v, ec, _ := testVerifier(t)
	now := time.Unix(1_800_000_000, 0)
	v.Now = func() time.Time { return now }
	at := func(exp time.Duration) string {
		return ec.token(t, claims(now, func(c map[string]any) {
			c["iat"], c["nbf"], c["exp"] = now.Add(-time.Minute).Unix(), now.Add(-time.Minute).Unix(), now.Add(exp).Unix()
		}), TokenType)
	}
	if _, err := v.VerifyToken(at(time.Second)); err != nil {
		t.Fatalf("a session token 1 s before its exp was refused: %v", err)
	}
	for _, d := range []time.Duration{0, -time.Second, -30 * time.Second} {
		if _, err := v.VerifyToken(at(d)); err == nil || err.Error() != "session token expired" {
			t.Fatalf("exp %v from now: %v, want session token expired", d, err)
		}
	}
	// nbf 30 s ahead (the gateway's clock ahead of the actor's): accepted.
	tok := ec.token(t, claims(now, func(c map[string]any) { c["nbf"] = now.Add(30 * time.Second).Unix() }), TokenType)
	if _, err := v.VerifyToken(tok); err != nil {
		t.Fatalf("nbf inside the skew was refused: %v", err)
	}
}
