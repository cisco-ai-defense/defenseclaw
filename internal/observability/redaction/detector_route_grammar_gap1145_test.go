// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package redaction

import (
	"strings"
	"testing"
)

// substrate-1:GAP-1145 (DET111 code area): the fixed route grammar of
// DefenseClaw's substrate API, the literal /api/v1/substrate/ prefix and its
// own path words, is not key material. It stays readable in an audit row's
// route and summary. The values after it are judged as before.
func TestSubstrateRouteGrammarStaysReadableGAP1145(t *testing.T) {
	t.Parallel()
	for _, route := range []string{
		"GET /api/v1/substrate/actors/{atespace}/{name}",
		"DELETE /api/v1/substrate/actors/{atespace}/{name}",
		"POST /api/v1/substrate/actors/{atespace}/{name}/policy/reset",
		"POST /api/v1/substrate/actors/{atespace}/{name}/recover",
		"POST /api/v1/substrate/actors/{atespace}/{name}/attach/{rest...}",
		"DELETE /api/v1/substrate/approvals/{atespace}/{name}/{host}",
		"POST /api/v1/substrate/secrets/{name}/test",
		"POST /api/v1/substrate/session-cert",
		"POST /api/v1/substrate/bundle/rollback",
		"GET /api/v1/substrate/policy/explain",
		"alice denied on eng-web/alice-1 (GET /api/v1/substrate/actors/{atespace}/{name}): not_your_agent, 1 attempt(s)",
	} {
		if got := redactAuditTarget(t, route); got != route {
			t.Errorf("route text redacted: %q -> %q", route, got)
		}
	}
}

// A secret-shaped value placed after or inside the fixed prefix is still
// redacted, and the grammar stays readable beside it.
func TestSecretAfterOrInsideTheRouteGrammarIsStillRedactedGAP1145(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, input, keep string }{
		{"after the prefix", "GET /api/v1/substrate/" + plantedPathToken, "/api/v1/substrate/"},
		{"after a path word", "GET /api/v1/substrate/actors/" + plantedPathToken, "/api/v1/substrate/actors/"},
		{"after two path words", "POST /api/v1/substrate/actors/" + plantedPathToken + "/recover", "/api/v1/substrate/actors/"},
		{"in a component that is not a path word", "GET /api/v1/substrate/actors" + plantedPathToken, ""},
		{"before the prefix", "GET " + plantedPathToken + "/api/v1/substrate/actors/", ""},
		{"a different prefix", "GET /api/v1/other/actors/" + plantedPathToken, ""},
		{"inside a word run", "GET /api/v1/substrate/actors/policy/" + plantedPathToken, "/api/v1/substrate/actors/policy/"},
	} {
		got := redactAuditTarget(t, tc.input)
		if strings.Contains(got, plantedPathToken) {
			t.Errorf("%s: token left in %q -> %q", tc.name, tc.input, got)
		}
		if tc.keep != "" && !strings.Contains(got, tc.keep) {
			t.Errorf("%s: route grammar lost beside the token: %q -> %q", tc.name, tc.input, got)
		}
	}
}
