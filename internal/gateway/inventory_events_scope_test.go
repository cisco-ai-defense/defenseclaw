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
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/inventory"
)

// TestEndpointInventoryScopeKeyDistinctForDifferentHomes asserts
// Vineet's [P1] identity gap: two users' same-named skills/plugins/MCP
// servers must not collapse to a single component id. The scope key
// derived from each home path must differ.
func TestEndpointInventoryScopeKeyDistinctForDifferentHomes(t *testing.T) {
	t.Parallel()
	a := endpointInventoryScopeKey("/Users/user1")
	b := endpointInventoryScopeKey("/Users/user2")
	if a == "" || b == "" {
		t.Fatalf("scope key must be non-empty for real home paths; got a=%q b=%q", a, b)
	}
	if a == b {
		t.Fatalf("distinct homes must yield distinct scope keys; both = %q", a)
	}
	// Absolutisation: relative path with same resolved absolute must
	// match the absolute-form scope, so a caller who forgot to
	// absolutise doesn't produce a phantom third scope. Only assert
	// non-emptiness here since the tempdir root varies by test run.
	if endpointInventoryScopeKey("") != "" {
		t.Fatal("empty path must yield empty scope, not a hash of the empty string")
	}
}

// TestEndpointInventoryScopeFromEvidenceUsesParentPathHash asserts the
// scope helper prefers the walker-provided PathHash on evidence[0]
// (the parent surface row) so scope keys stay stable across the
// walker's HMAC-key rotation. Different walker signals with different
// parent PathHashes must produce distinct scope tokens.
func TestEndpointInventoryScopeFromEvidenceUsesParentPathHash(t *testing.T) {
	t.Parallel()
	// Walker emits PathHash prefixed with "hmac-sha256:" or
	// "sha256:". The helper strips the prefix and takes the first 16
	// hex chars — enough to disambiguate but short enough to keep
	// the composed component id inside the wire schema's length
	// bound.
	sigA := []inventory.AIEvidence{
		{Type: "skill", PathHash: "hmac-sha256:aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbb"},
	}
	sigB := []inventory.AIEvidence{
		{Type: "skill", PathHash: "hmac-sha256:cccccccccccccccceeeeeeeeeeeeeeee"},
	}
	a := endpointInventoryScopeFromEvidence(sigA)
	b := endpointInventoryScopeFromEvidence(sigB)
	if a == b {
		t.Fatalf("distinct parent PathHashes must yield distinct scopes; both = %q", a)
	}
	if len(a) != 16 || len(b) != 16 {
		t.Fatalf("scope should be 16 hex chars; got a=%q (%d) b=%q (%d)", a, len(a), b, len(b))
	}
	if strings.Contains(a, ":") || strings.Contains(b, ":") {
		t.Fatal("scope must not include the sha256:/hmac-sha256: prefix")
	}
	if empty := endpointInventoryScopeFromEvidence(nil); empty != "" {
		t.Fatalf("empty evidence must yield empty scope; got %q", empty)
	}
}

// TestEndpointInventoryComponentIDDistinctAcrossScopes verifies that
// two identical (kind, sig-id, name) inputs with different scope
// tokens produce different component ids — the end-to-end contract of
// the identity fix. If this test ever passes with same IDs across
// scopes, the collapse Vineet flagged has regressed.
func TestEndpointInventoryComponentIDDistinctAcrossScopes(t *testing.T) {
	t.Parallel()
	// Simulate the concatenation the emit sites do:
	//   signalID + "/" + scope + "/" + name
	idA := endpointInventoryComponentID("skill-entry", "codex/aaaaaaaaaaaaaaaa/hello")
	idB := endpointInventoryComponentID("skill-entry", "codex/bbbbbbbbbbbbbbbb/hello")
	if idA == idB {
		t.Fatalf("same-name skill across scopes must have distinct ids; both = %q", idA)
	}
	// Same scope + same name -> same id (stability guarantee).
	idAgain := endpointInventoryComponentID("skill-entry", "codex/aaaaaaaaaaaaaaaa/hello")
	if idA != idAgain {
		t.Fatalf("component id must be stable for same inputs; got %q vs %q", idA, idAgain)
	}
}
