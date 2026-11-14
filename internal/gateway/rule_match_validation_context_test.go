// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestFirstAcceptedRegexMatchPreservesFullTextContext(t *testing.T) {
	t.Parallel()

	for _, pattern := range []string{`\bTOKEN`, `^TOKEN`} {
		pattern := pattern
		t.Run(pattern, func(t *testing.T) {
			calls := 0
			match := firstAcceptedRegexMatch(
				regexp.MustCompile(pattern),
				"TOKENTOKEN",
				func(string) bool {
					calls++
					return calls > 1
				},
			)
			if match != nil {
				t.Fatalf("cursor restart manufactured match at %v", match)
			}
			if calls != 1 {
				t.Fatalf("validator calls=%d, want one original-context candidate", calls)
			}
		})
	}
}

func TestFirstAcceptedRegexMatchRejectsTypedNil(t *testing.T) {
	t.Parallel()
	var pattern *regexp.Regexp
	if match := firstAcceptedRegexMatch(pattern, "candidate", func(string) bool { return true }); match != nil {
		t.Fatalf("typed-nil pattern returned match %v", match)
	}
	if match, normalized, ok := findAcceptedLocalSecretMatch(
		"candidate", "candidate", localSecretDetector{pattern: pattern},
	); ok || normalized || match != "" {
		t.Fatalf("typed-nil local detector returned %q normalized=%v ok=%v", match, normalized, ok)
	}
}

func TestCredibleSSNContextAlignsWideDelimitedHeader(t *testing.T) {
	t.Parallel()
	columns := make([]string, 0, 25)
	values := make([]string, 0, 25)
	for index := 0; index < 24; index++ {
		columns = append(columns, "wide_export_column_"+strings.Repeat("x", 8))
		values = append(values, strings.Repeat("v", 24))
	}
	columns = append(columns, "ssn")
	values = append(values, "731-42-8065")
	text := strings.Join(columns, ",") + "\n" + strings.Join(values, ",")
	start := strings.LastIndex(text, values[len(values)-1])
	if start < 0 || start-strings.LastIndex(text[:start], "ssn") <= 80 {
		t.Fatal("wide CSV fixture did not exceed the ordinary SSN label window")
	}
	if !credibleSSNContext(text, start, start+len(values[len(values)-1])) {
		t.Fatal("wide CSV record lost its aligned SSN header context")
	}

	columns[len(columns)-1] = "ssn_hash"
	nonRecord := strings.Join(columns, ",") + "\n" + strings.Join(values, ",")
	start = strings.LastIndex(nonRecord, values[len(values)-1])
	if credibleSSNContext(nonRecord, start, start+len(values[len(values)-1])) {
		t.Fatal("non-record ssn_hash column was treated as an SSN label")
	}
}

// Bare identifier shapes need their label, and the label is in the pack's
// pattern, where operators see it (rel-1-0-10 GAP-0171): a run of nine digits
// beside another one, a timestamp fraction, or a letter and seven digits in a
// JSON value or under a licence header is not an SSN or a driver's licence.
// Strict pack (both rules are disabled in default): the YAML pattern, then the
// rule's match validator, as the scanner runs them.
func TestBareIdentifierShapesNeedTheirLabel(t *testing.T) {
	pack := mustLoadRulePack(t, filepath.Join(guardrailPoliciesRoot(t), "strict"))
	matches := func(ruleID, text string) bool {
		pattern := regexp.MustCompile(rulePatternByID(t, pack, ruleID))
		validator := ruleMatchValidator(ruleID)
		for _, loc := range pattern.FindAllStringIndex(text, -1) {
			if validator == nil || validator(text, text[loc[0]:loc[1]], loc[0], loc[1]) {
				return true
			}
		}
		return false
	}
	for _, tc := range []struct {
		rule, text string
		want       bool
	}{
		{"ENT-BULK-SSN-NOHYPHEN", "<tr><td>order</td><td>731428065</td></tr><tr><td>order</td><td>624519873</td></tr>", false},
		{"ENT-BULK-SSN-NOHYPHEN", "2026-03-26 00:00:24.731428065 and 2026-03-26 00:00:25.624519873", false},
		{"ENT-BULK-SSN-NOHYPHEN", "employee ssn: 731428065", true},
		{"ENT-BULK-SSN-NOHYPHEN", `{"ssn_number": "731428065"}`, true},
		{"ENT-BULK-SSN-NOHYPHEN", "example ssn: 731428065", false},
		{"ENT-BULK-SSN-NOHYPHEN", "ssn_hash: 731428065", false},
		{"ENT-DL-CA", `{"status": "A1234567", "next": "B7654321"}`, false},
		{"ENT-DL-CA", "SPDX-License-Identifier: Apache-2.0\nbuild A1234567", false},
		{"ENT-DL-CA", "Driver licence: A1234567", true},
		{"ENT-DL-CA", `{"dl_number": "A1234567"}`, true},
		{"ENT-DL-CA", "CA DL A1234567", true},
	} {
		if got := matches(tc.rule, tc.text); got != tc.want {
			t.Errorf("%s on %q: match=%v, want %v", tc.rule, tc.text, got, tc.want)
		}
	}
}
