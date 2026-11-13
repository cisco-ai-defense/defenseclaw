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

package policy

import (
	"strings"
	"testing"
)

func TestPrepareCascadeRefusals(t *testing.T) {
	tests := []struct{ name, src, want string }{
		{"empty", "", "empty module"},
		{"other package", "package defenseclaw.guardrail\n", "want package defenseclaw.cascade"},
		{"parse error", "package defenseclaw.cascade\ndecisions contains {", "parse"},
		{"network builtin", "package defenseclaw.cascade\nimport rego.v1\ndecisions contains d if { r := http.send({\"method\": \"GET\", \"url\": \"https://example.invalid\"}); d := {\"action\": \"block\"} }\n", "http.send"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := PrepareCascade(t.Context(), []byte(tt.src))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("PrepareCascade = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestCascadeEvaluate(t *testing.T) {
	src := `package defenseclaw.cascade
import rego.v1

decisions contains {"action": "BLOCK", "id": "contractors", "reason": "contractors: HIGH blocks"} if {
	"contractors" in input.subject.profiles
}

decisions contains {"action": "alert", "reason": "notebooks"} if input.tool == "NotebookEdit"
`
	p, err := PrepareCascade(t.Context(), []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	got, err := p.Evaluate(t.Context(), map[string]any{"subject": map[string]any{"profiles": []any{"contractors"}}, "tool": "NotebookEdit"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("decisions = %+v", got)
	}
	ids := map[string]string{}
	for _, d := range got {
		ids[d.ID] = d.Action
	}
	if ids["contractors"] != "block" || ids["notebooks"] != "alert" {
		t.Fatalf("decisions = %+v (an id defaults to the reason)", got)
	}
	none, err := p.Evaluate(t.Context(), map[string]any{"subject": map[string]any{"profiles": []any{}}})
	if err != nil || len(none) != 0 {
		t.Fatalf("no match = %+v, %v", none, err)
	}
	if !strings.HasPrefix(p.Digest, "sha256:") {
		t.Fatalf("digest = %q", p.Digest)
	}
}

func TestCascadeEvaluateRefusesBadDecisions(t *testing.T) {
	for name, src := range map[string]string{
		"bad action": "package defenseclaw.cascade\nimport rego.v1\ndecisions contains {\"action\": \"deny\"} if true\n",
		"not object": "package defenseclaw.cascade\nimport rego.v1\ndecisions contains \"block\" if true\n",
		"too many":   "package defenseclaw.cascade\nimport rego.v1\ndecisions contains {\"action\": \"alert\", \"id\": sprintf(\"r%d\", [i])} if some i in numbers.range(1, 40)\n",
	} {
		t.Run(name, func(t *testing.T) {
			p, err := PrepareCascade(t.Context(), []byte(src))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := p.Evaluate(t.Context(), map[string]any{}); err == nil {
				t.Fatal("bad decisions accepted")
			}
		})
	}
}
