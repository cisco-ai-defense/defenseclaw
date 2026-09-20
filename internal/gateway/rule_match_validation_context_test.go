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
