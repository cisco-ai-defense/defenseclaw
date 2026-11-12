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

package envvars

import (
	"strings"
	"testing"
)

func TestShadowedAdoptedGatewayTokens(t *testing.T) {
	marker := AdoptedGatewayTokenMarker("adopted")
	for _, tc := range []struct {
		name string
		body string
		want []string
	}{
		{"a one-spelling edit shadows the adopted copy under the other spelling",
			"DEFENSECLAW_GATEWAY_TOKEN=adopted\nOPENCLAW_GATEWAY_TOKEN=edited\n" + marker + "\n",
			[]string{"DEFENSECLAW_GATEWAY_TOKEN"}},
		{"the same edit on the canonical spelling shadows the legacy copy",
			"DEFENSECLAW_GATEWAY_TOKEN=\"edited\"\nOPENCLAW_GATEWAY_TOKEN=adopted\n" + marker + "\n",
			[]string{"OPENCLAW_GATEWAY_TOKEN"}},
		{"untouched adopted copies shadow nothing",
			"DEFENSECLAW_GATEWAY_TOKEN=adopted\nOPENCLAW_GATEWAY_TOKEN=adopted\n" + marker + "\n", nil},
		{"without a marker nothing is known to be adopted",
			"DEFENSECLAW_GATEWAY_TOKEN=adopted\nOPENCLAW_GATEWAY_TOKEN=edited\n", nil},
		{"a marker for another value adopts nothing here",
			"DEFENSECLAW_GATEWAY_TOKEN=one\nOPENCLAW_GATEWAY_TOKEN=two\n" + marker + "\n", nil},
		{"one adopted spelling alone is the token",
			"OPENCLAW_GATEWAY_TOKEN=adopted\n" + marker + "\n", nil},
		{"a saved SecretRef text is not a competing token",
			"DEFENSECLAW_GATEWAY_TOKEN=adopted\nOPENCLAW_GATEWAY_TOKEN={\x27source\x27: \x27env\x27, \x27id\x27: \x27X\x27}\n" + marker + "\n", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := ShadowedAdoptedGatewayTokens([]byte(tc.body))
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Fatalf("shadowed = %v, want %v", got, tc.want)
			}
			for _, name := range tc.want {
				if !got.Has(name) {
					t.Errorf("Has(%q) = false", name)
				}
			}
			if got.Has("DEFENSECLAW_LLM_KEY") {
				t.Error("an unrelated key must never be shadowed")
			}
		})
	}
}

func TestAdoptedGatewayTokenMarkerIsAComment(t *testing.T) {
	line := AdoptedGatewayTokenMarker("adopted")
	if !strings.HasPrefix(line, "#") || !IsAdoptedGatewayTokenMarker(line) {
		t.Fatalf("marker %q must be a recognized comment line", line)
	}
	if strings.Contains(line, "adopted gateway token sha256=adopted") {
		t.Fatal("the marker records a digest, never the token")
	}
}

// The Python CLI reads the same marker (cli/defenseclaw/gateway_token_adoption.py);
// cli/tests/test_gateway_token_adoption.py asserts this same line.
func TestAdoptedGatewayTokenMarkerMatchesThePythonReader(t *testing.T) {
	const want = "# defenseclaw: adopted gateway token sha256=5d4686f6ad6a5e224c3961e4d3ed3c65f192697ec734fa02b244e42df5900a84"
	if got := AdoptedGatewayTokenMarker("adopted"); got != want {
		t.Fatalf("marker = %q, want %q", got, want)
	}
}
