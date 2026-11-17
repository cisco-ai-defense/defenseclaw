// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package redaction

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/observability"
)

// GAP-0520: a Substrate actor name (readable words plus a hex suffix) is
// attribution data; the high-entropy detector no longer replaces it, while
// real high-entropy values in the same shape class are still found.
func TestActorNamesAreNotHighEntropySecretsGAP0520(t *testing.T) {
	t.Parallel()
	for _, name := range []string{
		"lg411gva-5-bffaeefc", "fix-tests-1a2b3c4d", "j37-g3-99-f9a7a28c", "claude-b66c97d1", "sub-j41-amp-0f3c9e2a77d1",
	} {
		if validHighEntropy(name, observability.FieldClassContent) && !labelWithSuffixShaped(name) {
			t.Errorf("%s is still a high-entropy secret", name)
		}
		if !labelWithSuffixShaped("dc-eng/" + name) {
			t.Errorf("dc-eng/%s does not read as an actor", name)
		}
		assertDetectorAbsent(t, "secrets.high_entropy", "task finished: dc-eng/"+name+" exit 0 after 7s")
	}
	for _, secret := range []string{
		"Zq8xR2mN7vK4tL9wB3cY6hJ1pD5sF0gA", // mixed case, no words
		"aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY",
		"k3j4h5g6f7d8s9a0-q1w2e3r4t5y6u7i8", // no readable word
		"dc-eng/Zq8xR2mN7vK4tL9wB3cY6hJ1",   // an atespace in front of a secret
	} {
		if labelWithSuffixShaped(secret) {
			t.Errorf("%s reads as an actor name", secret)
		}
	}
}
