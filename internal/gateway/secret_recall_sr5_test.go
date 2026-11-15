// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"math/rand"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// Regression rows for the fourth review of s7/secret-recall (GAP-0452,
// GAP-0453, GAP-0454). Every secret-shaped value is generated at run time
// from a seeded generator and never appears in the source.

const (
	lowerDigitAlphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	lowerAlphabet      = "abcdefghijklmnopqrstuvwxyz"
	hexAlphabet        = "0123456789abcdef"
	djangoAlphabet     = "abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*(-_=+)"
)

// GAP-0452: a generated value with a separator is not a name, whatever its
// letter runs look like, and a value may hold = ( and ).
func TestSecretAssignmentGeneratedValuesWithSeparatorsAreNotNames(t *testing.T) {
	r := rand.New(rand.NewSource(452))
	const n = 2000
	for _, class := range []struct {
		name string
		gen  func() string
		min  float64
	}{
		{"lower+digit 24 with a dash", func() string {
			v := randomString(r, lowerDigitAlphabet, 24)
			return v[:11] + "-" + v[12:]
		}, 0.95},
		{"lower+digit 16 with one underscore", func() string {
			v := randomString(r, lowerDigitAlphabet, 16)
			return v[:4] + "_" + v[5:]
		}, 0.92},
		{"alnum 24 with an underscore", func() string {
			v := randomString(r, alnumAlphabet, 24)
			return v[:11] + "_" + v[12:]
		}, 0.97},
		{"TOKEN_ and 32 hex", func() string { return "TOKEN_" + randomString(r, hexAlphabet, 32) }, 0.99},
		{"word_ and 12 lower+digit", func() string { return "prod_" + randomString(r, lowerDigitAlphabet, 12) }, 0.83},
		{"word_word_ and 16 random digits", func() string {
			return "summer_holiday_" + randomString(r, "0123456789", 16)
		}, 0.97},
		{"base64url 32 bytes", func() string { return randomBase64(r, 32, true) }, 0.97},
		{"django style 50", func() string { return randomString(r, djangoAlphabet, 50) }, 0.97},
	} {
		t.Run(class.name, func(t *testing.T) {
			accepted := 0
			for i := 0; i < n; i++ {
				if acceptedSecretAssignment("SECRET_KEY = " + class.gen()) {
					accepted++
				}
			}
			// A random lower case run is a word-shaped run of three letters or more
			// some of the time, so the bar of the classes with fewer digits is
			// lower; before the digits counted these were accepted 87%, 84% and
			// 62% (review G2, G12, G7) and the long-number class 11%.
			if share := float64(accepted) / n; share < class.min {
				t.Fatalf("accepted %.3f of %d values, want at least %.2f", share, n, class.min)
			}
		})
	}
}

// What a person composed from words and a counter is still a name.
func TestSecretAssignmentWordsAndCountersAreStillNames(t *testing.T) {
	r := rand.New(rand.NewSource(453))
	for _, value := range []string{
		"dr_secret_key_" + randomString(r, "0123456789", 10),
		"dr_secret_key_1700000000", "dr_secret_key_1700000000000",
		"summer-holiday-2026", "my-favourite-band-1999", "internal_service_config_v2",
		"production_database_backup_20261113",
	} {
		if got := secretAssignmentRejection(value); got == "" {
			t.Errorf("a composed name was accepted as a secret: %q", value)
		}
	}
}

// A call is not a value, a random key holding "(" is.
func TestSecretAssignmentCallAndParenthesisedValue(t *testing.T) {
	r := rand.New(rand.NewSource(454))
	for _, call := range []string{"get_token(request)", "os.getenv(NAME_OF_SETTING)", "make_secret_key(application)", "fetchSecretFromVault(client)"} {
		if got := secretAssignmentRejection(call); got != "call" && got != "reference" {
			t.Errorf("%q rejected as %q, want a call or a reference", call, got)
		}
	}
	// A "(" inside the first twelve characters of a Django-style key.
	key := randomString(r, "abcdefghijklmnopqrstuvwxyz0123456789", 4) + "(" + randomString(r, djangoAlphabet, 45) + "a1"
	if got := secretAssignmentRejection(key); got != "" {
		t.Errorf("a key with a parenthesis in it was rejected as %q", got)
	}
	// A closing parenthesis of the code around the value is not part of it.
	if got, want := secretAssignmentRejection(randomString(r, alnumAlphabet, 24)+")"), ""; got != want {
		t.Errorf("a value followed by a closing parenthesis was rejected as %q", got)
	}
}

func TestSecretAssignmentDjangoKeyThroughTheHook(t *testing.T) {
	const connector = "secret-recall-sr5-test"
	installDefaultProfileConnector(t, connector)
	r := rand.New(rand.NewSource(455))
	key := randomString(r, "abcdefghijklmnopqrstuvwxyz0123456789", 3) + "(" + randomString(r, djangoAlphabet, 46) + "x1"
	args := map[string]any{"file_path": "/work/app/settings.py", "content": "SECRET_KEY = '" + key + "'\n"}
	if got := reviewDisposition(t, connector, "Write", args); got != credAlert {
		t.Fatalf("Django-style key with a parenthesis: disposition = %s, want %s", got, credAlert)
	}
}

// GAP-0453: the documented AWS example is exempt only when nothing meaningful
// follows it.
func TestAWSDocumentedExampleRemainderRows(t *testing.T) {
	r := rand.New(rand.NewSource(456))
	doc := awsDocumentedSecretKey
	flat := strings.ReplaceAll(doc, "/", "")
	random := func(n int) string { return randomString(r, alnumAlphabet, n) }
	code := func(n int) string { return randomString(r, "+=", n) }
	for _, test := range []struct {
		id        string
		candidate string
		finding   bool
	}{
		{"A1 the documented value", doc, false},
		{"A2 value, escapes and a rule line", flat + "nnn" + strings.Repeat("=", 79) + "nnSummary", false},
		{"A2b value and escapes", flat + "nnnn", false},
		{"A2c value, escapes, a rule line and a lower case word", flat + "nrt" + strings.Repeat("+", 40) + "nnsummary", false},
		{"A3 value and 40 random", flat + random(40), true},
		{"A4 value and a secret in a +/= code of 240", flat + code(240), true},
		{"A4b value and a long run of =", flat + strings.Repeat("=", 240), true},
		{"A4c value and a short +/= code", flat + code(40), true},
		{"A5 value and 12 random letters and digits", flat + random(12), true},
		{"A6 value with slashes and 12 random", doc + random(12), true},
		{"A7 random 40 alone", random(40), true},
		{"A8 value, slash runs and 12 random", doc + "///" + random(12), true},
		{"A9 value, a rule line and random", flat + "nnn=====" + random(12), true},
		{"A10 value and digits", flat + "nn20261113", true},
		{"A11 value and a random lower case run", flat + "nn" + randomString(r, "bcdfghjklmnpqrstvwxz", 12), true},
	} {
		t.Run(test.id, func(t *testing.T) {
			got := acceptedCredentialMatch("SEC-AWS-SECRET", "aws_secret_access_key = "+test.candidate)
			if got != test.finding {
				t.Fatalf("finding = %v, want %v", got, test.finding)
			}
		})
	}
	// The same random remainder across many seeds is always a finding.
	for i := 0; i < 500; i++ {
		if !acceptedCredentialMatch("SEC-AWS-SECRET", "aws_secret_access_key = "+flat+random(12)) {
			t.Fatalf("a documented value followed by 12 random letters and digits was exempt (draw %d)", i)
		}
	}
}

// GAP-0454: eight decoys do not hide a real labelled passport or card.
func TestOutboundPIIScansEveryMatch(t *testing.T) {
	card := runtimeDetectorSignature("4237-4252", "-7456-2574")
	decoyCards := strings.Repeat("Order 4237425274562574 shipped. ", 12)
	decoyPassports := strings.Repeat("Passport Number: ABCDEFGH\n", 12) // letters only: no digit
	for _, test := range []struct {
		name string
		body string
		rule string
	}{
		{"12 unlabelled cards then a labelled card", decoyCards + "Credit Card Number: " + card, "PII-CARD-LABELED"},
		{"12 decoy passports then a real one", decoyPassports + "Passport Number: HGK137803", "PII-PASSPORT-LABELED"},
		{"8 decoy passports then a real one", strings.Repeat("Passport Number: ABCDEFGH\n", 8) + "Passport Number: HGK137803", "PII-PASSPORT-LABELED"},
		{"500 decoy passports then a real one", strings.Repeat("Passport Number: ABCDEFGH\n", 500) + "Passport Number: HGK137803", "PII-PASSPORT-LABELED"},
	} {
		t.Run(test.name, func(t *testing.T) {
			raw, err := json.Marshal(map[string]any{"body": test.body})
			if err != nil {
				t.Fatal(err)
			}
			findings := outboundPIIFindings(trustedActionRequest{
				Input:              actionfacts.Input{Tool: "mcp__bench__send_email", Args: raw},
				EnforcementCapable: true,
			}, nil)
			for _, f := range findings {
				if f.RuleID == test.rule {
					return
				}
			}
			t.Fatalf("no %s finding behind the decoys", test.rule)
		})
	}
}
