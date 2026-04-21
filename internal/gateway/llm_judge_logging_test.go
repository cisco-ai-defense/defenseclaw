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

package gateway

import (
	"strings"
	"testing"
)

// TestRedactEntity covers the H2 fix: PII entities echoed back from the
// judge must never appear verbatim in logs. redactEntity must:
//   - Never include the raw input
//   - Be UTF-8 safe (no slicing across rune boundaries)
//   - Preserve enough metadata (length, first rune prefix) for operators
//     to triage false positives without leaking the value
func TestRedactEntity(t *testing.T) {
	tests := []struct {
		name         string
		in           string
		wantContains []string
		wantNot      string // must not appear in output
	}{
		{
			name: "empty",
			in:   "",
			wantContains: []string{
				"<empty>",
			},
		},
		{
			name: "short SSN-like",
			in:   "123",
			wantContains: []string{
				"len=3",
			},
			wantNot: "123",
		},
		{
			name: "exactly-4-char",
			in:   "1234",
			wantContains: []string{
				"len=4",
			},
			wantNot: "1234",
		},
		{
			name: "typical phone",
			in:   "4155551212",
			wantContains: []string{
				"len=10",
				"prefix=",
			},
			wantNot: "4155551212",
		},
		{
			name: "utf8 multibyte prefix",
			in:   "日本電話番号090",
			wantContains: []string{
				// Length in bytes, matching len(s) used by redactEntity.
				"len=21",
				"prefix=",
			},
			wantNot: "日本電話番号090",
		},
		{
			name: "email",
			in:   "alice@example.com",
			wantContains: []string{
				"len=17",
			},
			wantNot: "alice@example.com",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := redactEntity(tc.in)
			for _, want := range tc.wantContains {
				if !strings.Contains(got, want) {
					t.Errorf("redactEntity(%q)=%q, want substring %q", tc.in, got, want)
				}
			}
			if tc.wantNot != "" && strings.Contains(got, tc.wantNot) {
				t.Errorf("redactEntity(%q)=%q leaks raw value %q", tc.in, got, tc.wantNot)
			}
			// Sanity: prefix field (when present) must show only the first
			// rune, not the full value — verifies UTF-8 safety.
			if i := strings.Index(got, "prefix="); i >= 0 {
				// prefix=%q renders a quoted single rune. It must be at
				// most 1 rune wide when unquoted; a cheap proxy is that
				// the overall output length is much shorter than the raw
				// input would be.
				if len(got) > 64 {
					t.Errorf("redacted output unexpectedly long (%d) for %q: %q", len(got), tc.in, got)
				}
			}
		})
	}
}

// TestJudgeLogTraceFlag ensures the trace flag parser matches the documented
// accepted values and ignores anything else. Trace logging exposes raw PII
// and MUST default to off.
func TestJudgeLogTraceFlag(t *testing.T) {
	cases := map[string]bool{
		"":       false,
		"0":      false,
		"false":  false,
		"no":     false,
		"off":    false,
		" 0 ":    false,
		"1":      true,
		"true":   true,
		"TRUE":   true,
		"  Yes ": true,
		"on":     true,
	}
	for val, want := range cases {
		t.Setenv("DEFENSECLAW_JUDGE_TRACE", val)
		if got := judgeLogTrace(); got != want {
			t.Errorf("DEFENSECLAW_JUDGE_TRACE=%q judgeLogTrace()=%v want %v", val, got, want)
		}
	}
}
