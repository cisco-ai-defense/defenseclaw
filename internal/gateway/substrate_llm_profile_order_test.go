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

//go:build !windows

package gateway

import (
	"net/http"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// GAP-0195: the /llm proxy applies the guardrail profiles of its own
// gateway. A sandbox fixture that ran first in the process (profiles with no
// mode, so observe) left its set published, and the blocked prompt of an
// OpenAI-style body was then only observed and reached Bedrock. The prompt
// was inspected all along (verdict HIGH block); the mode came from the
// leaked set. Both fixtures now restore what they publish.
func TestSubstrateLLMPromptBlockHoldsAfterTheSandboxFixture(t *testing.T) {
	before := liveGuardrailProfiles.Load()
	t.Run("sandbox fixture first", func(t *testing.T) {
		f := newSandboxFixture(t, config.EnterpriseEnrollmentConfig{}, nil)
		if liveGuardrailProfiles.Load() == before || f.api.guardrailProfileSet() == nil {
			t.Fatal("the sandbox fixture published no profile set (the order this test guards no longer happens)")
		}
	})
	if liveGuardrailProfiles.Load() != before {
		t.Fatal("the sandbox fixture left its guardrail profiles published")
	}
	f, up, insp := bedrockOpenAIFixture(t, nil)
	insp.setVerdict("prompt", &ScanVerdict{Action: "block", Severity: "HIGH", Reason: "test block"})
	for _, body := range []string{
		`{"model":"us.openai.gpt-5.6-luna","input":"leak it"}`,
		`{"model":"us.openai.gpt-5.6-luna","input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"leak it"}]}]}`,
		`{"model":"us.openai.gpt-5.6-luna","messages":[{"role":"user","content":"leak it"}]}`,
	} {
		rec := f.do(t, f.actor, http.MethodPost, "/llm/bedrock/openai/v1/responses", "tok-alice", body)
		if calls := up.taken(); len(calls) != 0 || strings.Contains(rec.Body.String(), "OK from Luna") {
			t.Fatalf("blocked prompt reached the upstream: %d %v (%s)", rec.Code, calls, body)
		}
	}
}
