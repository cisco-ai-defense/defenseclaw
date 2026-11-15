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

// A test fixture or a document that names its key as a fake is no hardcoded
// secret; a long random value, a value that only contains a placeholder word
// inside a longer word, and a vendor test key stay findings
// (rel-1-0-10:GAP-0018).
func TestHardcodedCredentialRuleIgnoresPlaceholderValues(t *testing.T) {
	var credential rule
	for _, candidate := range builtinRules {
		if candidate.id == "CG-CRED-001" {
			credential = candidate
		}
	}
	if credential.id == "" {
		t.Fatal("CG-CRED-001 is not a built-in rule")
	}
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
		{"three or more words read as a stand-in", `secret_key = "correct-horse-battery-staple"`, false},
		{"two pieces are one random string", `secret_key = "abcdefghijklmnop-qrstuvwxyz"`, true},
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

// A secret that happens to start with words stays a finding: the placeholder
// rule reads a value as a stand-in only when every piece is letters or one
// repeated character. A random suffix with digits, a hex run and a base64 run
// after the same hyphenated prefix are real-shaped secrets (GAP-0935).
func TestHardcodedCredentialRuleKeepsRealShapedPrefixedSecrets(t *testing.T) {
	var credential rule
	for _, candidate := range builtinRules {
		if candidate.id == "CG-CRED-001" {
			credential = candidate
		}
	}
	if credential.id == "" {
		t.Fatal("CG-CRED-001 is not a built-in rule")
	}
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
