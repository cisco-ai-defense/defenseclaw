// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import "testing"

// GAP-0934: the profile policy digest covers guardrail.cisco_trust_level,
// which decides whether Cisco AI Defense verdicts block; the default (full)
// leaves the digest as it was.
func TestGuardrailPolicyDigestCoversCiscoTrustLevel(t *testing.T) {
	digest := func(level string) string {
		t.Helper()
		cfg := &Config{Guardrail: GuardrailConfig{Mode: "action", BlockAt: "high", CiscoTrustLevel: level}}
		got, err := GuardrailPolicyDigest(cfg)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	full := digest("")
	if digest("full") != full || digest("FULL") != full {
		t.Fatal("the default trust level changed the digest")
	}
	if digest("none") == full || digest("advisory") == full || digest("none") == digest("advisory") {
		t.Fatal("a policy that changed only cisco_trust_level has the same digest")
	}
}
