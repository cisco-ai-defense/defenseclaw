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

package scanner

import "testing"

func credentialRule(t *testing.T) rule {
	t.Helper()
	for _, candidate := range builtinRules {
		if candidate.id == "CG-CRED-001" {
			return candidate
		}
	}
	t.Fatal("CG-CRED-001 is not a built-in rule")
	return rule{}
}

// A test fixture or a document that names its key as a fake is no hardcoded
// secret; a long random value, a value that only contains a placeholder word
// inside a longer word, and a vendor test key stay findings
// (rel-1-0-10:GAP-0018).
func TestHardcodedCredentialRuleIgnoresPlaceholderValues(t *testing.T) {
	credential := credentialRule(t)
	for _, tc := range []struct {
		name, line string
		fires      bool
	}{
		{"fake token", `SENDGRID_API_KEY = "SG.fake.sendgrid.test.token"  # fixture only`, false},
		{"example key", `api_key = "your-api-key-example-0000"`, false},
		{"dummy secret", `secret_key: 'dummy_secret_value_for_tests'`, false},
		{"one repeated character", `API_KEY = "xxxxxxxxxxxxxxxxxxxx"`, false},
		{"zeros", `access_token = "0000000000000000"`, false},
		{"real shaped key", `api_key = "9f8e7d6c5b4a39281706f5e4d3c2b1a0"`, true},
		{"placeholder word inside a longer word", `api_key = "fakirjewelrysecretvalue12"`, true},
		{"vendor test key", "api_key = \"sk" + "_test_" + "4eC39HqLyjWDarjtT1zdp7dc\"", true},
		{"placeholder beside a real key", `a = {api_key: "fake_value_for_docs_only", secret_key: "9f8e7d6c5b4a39281706f5e4d3c2b1a0"}`, true},
		{"words without a stand-in word are a passphrase", `secret_key = "correct-horse-battery-staple"`, true},
		{"the alphabet in two pieces is a sequence", `secret_key = "abcdefghijklmnop-qrstuvwxyz"`, false},
		{"a piece with a digit and a letter mix is a key", `api_key = "build.number.7f3a9c.release"`, true},
		{"short value", `api_key = "short"`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := credential.matches(tc.line); got != tc.fires {
				t.Fatalf("matches(%q) = %t, want %t", tc.line, got, tc.fires)
			}
		})
	}
}

// Only a low-entropy shape is a placeholder: a repeated or sequential run, a
// stand-in word, a template slot. A random letters-only value after a key
// prefix is a finding at every length and case, as on rel (GAP-0942). The
// values below are made up for the test.
func TestHardcodedCredentialRuleLowEntropyPlaceholdersOnly(t *testing.T) {
	credential := credentialRule(t)
	const prefix = "codeguard-private-value-"
	for _, tc := range []struct {
		name, value string
		fires       bool
	}{
		{"random letters mixed case", prefix + "QwhTzrPkvMbnXcLsdGyFjRea", true},
		{"random letters lower case", prefix + "qhtzrpkvmbnxclsdgyfjreaw", true},
		{"random letters upper case", prefix + "QHTZRPKVMBNXCLSDGYFJREAW", true},
		{"random letters long", prefix + "pXrTqWzKmNbVcLsDfGhJyUiOeAqWsEdRfTgYhUjIkOlPz", true},
		{"random letters long alone", "pXrTqWzKmNbVcLsDfGhJyUiOeAqWsEdRfTgYhUjIkOlPzQ", true},
		{"random letters short", prefix + "QwhTzrPkvM", true},
		{"random letters short lower", prefix + "qhtzrpkv", true},
		{"random letters twelve", prefix + "hjkqwzxvbnmt", true},
		{"random letters after a stand-in word", "test-QwhTzrPkvMbnXcLsdGyFjRea", true},
		{"random letters long after a stand-in word", "example_qhtzrpkvmbnxclsdgyfjreaw", true},
		{"repeated character", prefix + "qqqqqqqqqqqqqqqqqqqqqqqq", false},
		{"repeated unit", "abcabcabcabcabcabcabc", false},
		{"sequential letters", prefix + "abcdefghijklmnopqrstuvwx", false},
		{"sequential digits", "0123456789012345"[:10] + "-abcdefghij", false},
		{"descending run", "zyxwvutsrqponmlk", false},
		{"word example", "example-key-for-the-docs", false},
		{"word your", "your-secret-key-goes-here", false},
		{"word xxx", "sk-xxx-replace-with-real", false},
		{"word changeme", "changeme-before-production", false},
		{"word placeholder", "placeholder_secret_value", false},
		{"word dummy", "dummy-access-token-value", false},
		{"word sample", "sample.access.token.value", false},
		{"word test", "test_secret_key_for_ci_only", false},
		{"word redacted", "REDACTED-REDACTED-REDACTED", false},
		{"angle template", "<your-api-key-here>", false},
		{"angle template upper", "<PRIVATE_KEY_VALUE_GOES_HERE>", false},
		{"dollar template", "${OPENAI_API_KEY_FROM_ENV}", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			line := "api_key = \"" + tc.value + "\""
			if got := credential.matches(line); got != tc.fires {
				t.Fatalf("matches(%q) = %t, want %t", line, got, tc.fires)
			}
		})
	}
}

// A stand-in word, run or template excuses a value only when no other piece
// reads as random: beside a stand-in, a single-case letters run longer than
// the measured placeholder max (10), a piece with three case rises, or a
// letters and digits mix is a finding, as on rel (GAP-0957). The values are
// made up; the GAP-0957 review probe ids are in the names.
func TestHardcodedCredentialRuleStandInBesideRandomPiece(t *testing.T) {
	credential := credentialRule(t)
	for _, tc := range []struct {
		name, value string
		fires       bool
	}{
		{"B07 random run then test", "qhtzrpkvmbnxcls-test", true},
		{"B08 test then random run", "test-qhtzrpkvmbnxcls", true},
		{"B11 your then two case rises", "your-QhtzrPkvmbnxcl", true},
		{"B12 random run then a sequence", "qhtzrpkvmbnxcls-abcdefgh", true},
		{"B13 vendor test prefix then random run", "sk_test_qhtzrpkvmbnxcls", true},
		{"B14 angle template around a random key", "<Qh7tZ3rP9kVm4BnX2cLs>", true},
		{"B15 dollar template around a random key", "${Qh7tZ3rP9kVm4BnX2cLs}", true},
		{"B19 fake then upper-case random run", "fake-QHTZRPKVMBNXCLS", true},
		{"random run eleven beside example", "example-wjqzrtkvmhn", true},
		{"stand-in between random runs", "wjqzrtkvmhnpx_sample_wjqzrtkvmhnpx", true},
		{"two stand-in words and one random run", "your-fake-wjqzrtkvmhnpxbd", true},
		{"stand-in after mixed case", "PwqZtrKvmHnx-dummy", true},
		{"template around stand-in then random run", "<test-wjqzrtkvmhnpxbd>", true},
		{"stand-in word and a repeated run", "test-qqqqqqqqqqqqqqqqqqqq", false},
		{"stand-in word and a sequence", "your-abcdefghijklmnopqrst", false},
		{"two stand-in words and a sequence", "fake-test-0123456789", false},
		{"stand-in word and ten-letter words", "changeme-before-production", false},
		{"template of words", "<PRIVATE_KEY_VALUE_GOES_HERE>", false},
		{"template of a repeated run", "<xxxxxxxxxxxxxxxxxxxx>", false},
		{"template of separators only", "${_________________}", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			line := "api_key = \"" + tc.value + "\""
			if got := credential.matches(line); got != tc.fires {
				t.Fatalf("matches(%q) = %t, want %t", line, got, tc.fires)
			}
		})
	}
}

// A secret that happens to start with words stays a finding: the placeholder
// rule reads a value as a stand-in only when every piece is letters or one
// repeated character. A random suffix with digits, a hex run and a base64 run
// after the same hyphenated prefix are real-shaped secrets (GAP-0935).
func TestHardcodedCredentialRuleKeepsRealShapedPrefixedSecrets(t *testing.T) {
	credential := credentialRule(t)
	const prefix = "codeguard-private-value-"
	for _, tc := range []struct {
		name, value string
		fires       bool
	}{
		{"mixed case and digits", prefix + "Kq7vZ3mX9bTn4RwP2sLd8HcY", true},
		{"mixed case digits after a short prefix", "k-Kq7vZ3mX9bTn4RwP2sLd8HcY", true},
		{"hex run", prefix + "9f8e7d6c5b4a39281706f5e4d3c2b1a0", true},
		{"long hex run", prefix + "3b7e1c9a5d2f48608e1b4c7a9d3f5e2160b8c4a7", true},
		{"base64 run", prefix + "aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5bC7d", true},
		{"base64 run with symbols", prefix + "aB3d+E5fG/7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5bC7d==", true},
		{"repeated character is a stand-in", prefix + "qqqqqqqqqqqqqqqqqqqqqqqq", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			line := "api_key = \"" + tc.value + "\""
			if got := credential.matches(line); got != tc.fires {
				t.Fatalf("matches(%q) = %t, want %t", line, got, tc.fires)
			}
		})
	}
}
