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

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/paymentcard/testcorpus"
)

func csEmailSeverity(text string) (Severity, int) {
	best := Severity("")
	lists := 0
	for _, f := range csPIIScanContent([]byte(text), "f.txt") {
		switch f.RuleID {
		case "CS-PII-EMAIL-LIST":
			lists++
			best = SeverityMedium
		case "CS-PII-EMAIL":
			if best == "" {
				best = SeverityLow
			}
		}
	}
	return best, lists
}

// substrate-1:GAP-0149 / GAP-0159: clawshield follows the guardrail email
// rule: one address LOW, five or more distinct addresses MEDIUM (once).
func TestClawShieldEmailSingleLowListMedium(t *testing.T) {
	for _, c := range testcorpus.EmailPositive(3, 2) {
		if c.Kind != "csv-50-rows" && c.Kind != "comma-list" && c.Kind != "semicolon-list" && c.Kind != "mailto-links" {
			continue
		}
		sev, lists := csEmailSeverity(c.Text)
		if sev != SeverityMedium || lists != 1 {
			t.Errorf("%s: severity %q, %d list findings; want MEDIUM once", c.Kind, sev, lists)
		}
	}
	for _, c := range testcorpus.EmailBenign(3, 2) {
		if c.Kind != "vendor-instructions" && c.Kind != "single-contact" {
			continue
		}
		if sev, _ := csEmailSeverity(c.Text); sev != SeverityLow {
			t.Errorf("%s: severity %q, want LOW", c.Kind, sev)
		}
	}
}
