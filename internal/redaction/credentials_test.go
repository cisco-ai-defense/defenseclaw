// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package redaction

import (
	"errors"
	"strings"
	"testing"
)

// TestAssertNoCredentials_DetectsKnownPrefixes locks the contract for
// each format the scrub guard knows about. We never include the matched
// suffix in the error so the test asserts on the prefix label instead.
func TestAssertNoCredentials_DetectsKnownPrefixes(t *testing.T) {
	cases := []struct {
		name  string
		value string
		label string
	}{
		{"openai", "Bearer sk-abcdefghij1234567890_-+ABCDEF", "openai-key"},
		{"openai-project", "sk-proj-abcdefghij1234567890123456_-+ABCDEF", "openai-project-key"},
		{"anthropic", "sk-ant-abcdefghij1234567890123456_-+ABCDEF", "anthropic-key"},
		{"openrouter", "sk-or-abcdefghij1234567890123456_-+ABCDEF", "openrouter-key"},
		{"stripe-live", "Authorization: Bearer sk_live_abcdefghij1234567890_-+ABCDEF", "stripe-secret-live"},
		{"stripe-test", "sk_test_abcdefghij1234567890_-+ABCDEF", "stripe-secret-test"},
		{"aws-akia", "AKIAIOSFODNN7EXAMPLE", "aws-access-key"},
		{"google", "AIzaSyABCDEFGHIJ_-LMNOPQRSTUVWXYZ12345678", "google-api-key"},
		{"github-pat", "ghp_abcdefghijABCDEFGHIJ1234567890_-+ABCD", "github-pat"},
		{"slack-bot", "xoxb-abcdefghijklmnopqrstuvwxyz", "slack-bot"},
		{"jwt", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ4In0.abcdef", "jwt"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := AssertNoCredentials(c.value)
			if err == nil {
				t.Fatalf("expected detection for %s, got nil", c.label)
			}
			if !errors.Is(err, ErrCredentialDetected) {
				t.Fatalf("expected ErrCredentialDetected, got %v", err)
			}
			if !strings.Contains(err.Error(), c.label) {
				t.Fatalf("expected error to mention prefix label %q, got %q", c.label, err.Error())
			}
			// Critical: the matched value must NEVER appear in the error.
			if strings.Contains(err.Error(), c.value) {
				t.Fatalf("error leaked the matched value: %q", err.Error())
			}
		})
	}
}

// TestAssertNoCredentials_AllowsCleanValues confirms the common case
// of routing metadata is a no-op (no false positives).
func TestAssertNoCredentials_AllowsCleanValues(t *testing.T) {
	cases := []string{
		"",
		"api.openai.com",
		"/v1/chat/completions",
		"some_user_provided_string_with_dashes-and-numbers-1234",
		"sk", // too short — must NOT match the "sk-" prefix path
		"AKIA",
		"eyJ", // too short to be a JWT
	}
	for _, v := range cases {
		t.Run(v, func(t *testing.T) {
			if err := AssertNoCredentials(v); err != nil {
				t.Fatalf("unexpected detection for %q: %v", v, err)
			}
		})
	}
}

// TestAssertNoCredentials_MultipleFields checks that a credential
// landing in field[1] is reported as field[1], not field[0].
func TestAssertNoCredentials_MultipleFields(t *testing.T) {
	err := AssertNoCredentials("clean", "ghp_abcdefghijABCDEFGHIJ1234567890_-+ABCD", "also-clean")
	if err == nil {
		t.Fatal("expected detection")
	}
	if !strings.Contains(err.Error(), "field[1]") {
		t.Fatalf("expected field[1] in error, got %q", err.Error())
	}
}

// TestMustAssertNoCredentials_PanicsInTestMode is a smoke check that
// the dev-mode hard-fail tripwire fires under `go test`. Recover so
// the test itself doesn't crash.
func TestMustAssertNoCredentials_PanicsInTestMode(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic in test mode")
		}
		s, ok := r.(string)
		if !ok {
			t.Fatalf("expected string panic, got %T (%v)", r, r)
		}
		if !strings.Contains(s, "openai-key") {
			t.Fatalf("expected panic to mention openai-key prefix, got %q", s)
		}
	}()
	MustAssertNoCredentials("Bearer sk-abcdefghij1234567890_-+ABCD")
}
