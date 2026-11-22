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

func TestJudgeBoundsFreeTextOnlyForGemma(t *testing.T) {
	for model, want := range map[string]bool{"openai/gemma-4-31b": true, "google.gemma-4-31b": true, "gpt-4o-mini": false, "claude-haiku-5-5": false, "": false} {
		if got := judgeBoundsFreeText(model); got != want {
			t.Errorf("judgeBoundsFreeText(%q) = %v, want %v", model, got, want)
		}
	}
}

func TestJudgeSchemaBoundsEveryFreeTextField(t *testing.T) {
	for _, kind := range []string{"injection", "exfil", "pii", "adjudicate_injection", "tool_injection"} {
		plain := string(judgeResponseFormatFor(kind, false))
		bounded := string(judgeResponseFormatBounded(kind, false, true))
		if strings.Contains(plain, "maxLength") || strings.Contains(plain, "maxItems") {
			t.Errorf("%s: the default schema must not carry bounds: %s", kind, plain)
		}
		free := strings.Contains(plain, `"reasoning"`) || strings.Contains(plain, `"entities"`) || strings.Contains(plain, `"pattern"`)
		if free && !strings.Contains(bounded, "maxLength") {
			t.Errorf("%s: a schema with free text must be bounded: %s", kind, bounded)
		}
		if !free && bounded != plain {
			t.Errorf("%s: a schema with no free text must not change", kind)
		}
		if n := strings.Count(bounded, `"reasoning":{`); n != strings.Count(bounded, `"reasoning":{"maxLength":200,`) {
			t.Errorf("%s: every one of %d reasoning fields must carry maxLength 200: %s", kind, n, bounded)
		}
		// tool-safe keys keep the bounds
		if free && !strings.Contains(string(judgeResponseFormatBounded(kind, true, true)), "maxLength") {
			t.Errorf("%s: the tool-safe schema lost the bounds", kind)
		}
	}
}
