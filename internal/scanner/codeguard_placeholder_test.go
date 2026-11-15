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
