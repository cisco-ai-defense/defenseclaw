// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package redaction

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/observability"
)

// GAP-0520: a Substrate actor name ([<atespace>/]<words>[-<n>]-<6 or 8
// hex>) is attribution data; the high-entropy detector no longer replaces
// it. The exception is anchored to that shape, so no real secret shape gets
// through (narrow review, T6).
func TestActorNamesAreNotHighEntropySecretsGAP0520(t *testing.T) {
	t.Parallel()
	for _, name := range []string{
		"lg411gva-5-bffaeefc", "fix-tests-1a2b3c4d", "claude-b66c97d1", "dcad-r102-eng1-4f9c3a", "sub-j41-amp-0f3c9e2a",
		"dc-eng/lg411gva-5-bffaeefc", "eng-web/fix-the-tests-0a1b2c3d", "t/agent-4f9c3a",
	} {
		if !labelWithSuffixShaped(name) {
			t.Errorf("%s does not read as an actor name", name)
		}
		assertDetectorAbsent(t, "secrets.high_entropy", "task finished: "+name+" exit 0 after 7s")
	}
}

// The values the exception must never cover: each is still found by the
// high-entropy detector, as it was before.
func TestActorNameExceptionLetsNoSecretThroughGAP0520(t *testing.T) {
	t.Parallel()
	for name, secret := range map[string]string{
		"bare lower-case hex token":       "9f3c1a7e5b2d4c6a8e0f1b3d5a7c9e2f7d1b",
		"lower-cased AWS secret key":      strings.ToLower("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEYz9"),
		"lower-cased AWS key with dashes": "wjalrxutnfemi-k7mdeng-bpxrfi-c3d4e5f6",
		"GitHub token without its prefix": "zq8xr2mn7vk4tl9wb3cy6hj1pd5sf0ga2eui",
		"word-word and 13 hex":            "build-cache-0123456789abc",
		"word-word and 16 hex":            "build-cache-0123456789abcdef",
		"a long number before the suffix": "run-1234567890-bffaeefc",
		"no readable word":                "k3j4-h5g6-f7d8s9a0",
		"upper case":                      "Build-Cache-BFFAEEFC",
		"atespace in front of a secret":   "dc-eng/zq8xr2mn7vk4tl9wb3cy6hj1pd5sf0ga",
		"two slashes":                     "dc-eng/x/fix-tests-1a2b3c4d",
		"32 hex then two 8-hex groups":    "9f3c1a7e5b2d4c6a8e0f1b3d5a7c9e2f" + "-bffaeefc-1a2b3c4d",
		"long lower-case alnum group":     "k3j4h5g6f7d8s9a0q1w2e3r4-deadbeef",
		"long lower-case alnum middle":    "run-k3j4h5g6f7d8s9a0q1w2-bffaeefc",
		"mixed random group as a word":    "a1b2c3d4e5f6-bffaeefc",
		"hex-only group as a word":        "cafebabe-bffaeefc",
		"random atespace in front":        "k3j4h5g6f7d8s9a0q1w2e3r4t5y6u7i8o9p0a1s2d3f4g5h6j7k8l9z0x1c2v3b/fix-tests-1a2b3c4d",
		"too many segments":               "aaa-bbb-ccc-ddd-eee-fff-1a2b3c4d",
		"random letters as words":         "qzkvmp-xtrbwd-bffaeefc",
		"thirteen-letter group":           "abcdefghijklm-bffaeefc",
	} {
		if labelWithSuffixShaped(secret) {
			t.Errorf("%s (%s) reads as an actor name", name, secret)
		}
	}
	// The detector still replaces these shapes in text.
	for _, secret := range []string{
		"Zq8xR2mN7vK4tL9wB3cY6hJ1pD5sF0gA",
		"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	} {
		if !validHighEntropy(secret, observability.FieldClassContent) {
			t.Errorf("%s is no longer a high-entropy secret", secret)
		}
	}
}
