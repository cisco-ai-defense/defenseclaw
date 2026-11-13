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
		{"short value", `api_key = "short"`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := credential.matches(tc.line); got != tc.fires {
				t.Fatalf("matches(%q) = %t, want %t", tc.line, got, tc.fires)
			}
		})
	}
}
