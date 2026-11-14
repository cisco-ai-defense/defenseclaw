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

//go:build s7bench

package gateway

import "testing"

// In the bench build the same call gets the same nonce, a different call or
// session another one, and the shape is the gateway's.
func TestS7BenchNonceIsDerivedFromTheCall(t *testing.T) {
	a, b := toolJudgeNonceFor("s1\x00Bash\x00ls"), toolJudgeNonceFor("s1\x00Bash\x00ls")
	if a != b {
		t.Fatalf("same call, nonces %q and %q", a, b)
	}
	if a == toolJudgeNonceFor("s2\x00Bash\x00ls") || a == toolJudgeNonceFor("s1\x00Bash\x00pwd") {
		t.Fatal("a different session or call got the same nonce")
	}
	if !toolJudgeNonceShape.MatchString(a) {
		t.Fatalf("nonce shape %q", a)
	}
}
