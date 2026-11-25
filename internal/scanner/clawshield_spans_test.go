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
	"strings"
	"testing"
)

// Key-shaped literals are assembled at run time so the source holds none.
func b1Token(prefix string, n int) string {
	return prefix + strings.Repeat("Q7", n/2) + strings.Repeat("x", n%2)
}

func TestB1SpansCoverValueNotKeyName(t *testing.T) {
	gh := b1Token("gh"+"p_", 36)
	aws := b1Token("", 40)
	src := "token = \"" + gh + "\"\naws_secret_access_key = \"" + aws + "\"\nname = \"ok\"\n"
	spans := NewClawShieldSecretsScanner().ScanContentSpans([]byte(src))
	if len(spans) != 2 {
		t.Fatalf("spans = %+v, want 2", spans)
	}
	got := []string{src[spans[0].Start:spans[0].End], src[spans[1].Start:spans[1].End]}
	if got[0] != gh || got[1] != aws {
		t.Fatalf("span values = %q, want the token and the 40-char key only", got)
	}
	if !SigningKeyRule(spans[1].RuleID) || SigningKeyRule(spans[0].RuleID) {
		t.Fatalf("signing rules wrong: %+v", spans)
	}
}

func TestB1SpansWholeFileRules(t *testing.T) {
	src := `{"type": "service_account", "project_id": "p"}`
	spans := NewClawShieldSecretsScanner().ScanContentSpans([]byte(src))
	if len(spans) != 1 || !spans[0].Whole {
		t.Fatalf("spans = %+v, want one Whole span", spans)
	}
}
