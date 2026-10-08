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

package manager

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
	"github.com/defenseclaw/defenseclaw/internal/openshell/profiles"
)

// A model API can reject the model credential a sandbox was given (a
// short-term Bedrock key that expired, a revoked key). Claude Code retries
// for minutes, then ends the turn with its own advice (/login, which does
// not apply to a key DefenseClaw shares), while DefenseClaw saw model calls
// and nothing else (GAP-0271). The StopFailure hook Claude Code fires when
// a turn ends on a model API error names the failure: the feed, the status
// and the session summary say the key was rejected and how a fresh one
// reaches the sandbox.

// modelKeyRejected reports whether d reports a model API that rejected the
// credential: an authentication failure, or HTTP 401.
func modelKeyRejected(d HookDecision) bool {
	return d.ModelError == "authentication_failed" || d.ModelStatus == http.StatusUnauthorized
}

// observeModelAnswerLocked notes what a hook event says of the model API:
// a rejected credential (returned, for the feed, the first time) or a turn
// that ended normally (Stop), which proves the credential works again.
func (b *box) observeModelAnswerLocked(d HookDecision, now time.Time) string {
	switch {
	case modelKeyRejected(d):
		first := b.hooks.modelRejectedAt.IsZero()
		b.hooks.modelRejected, b.hooks.modelRejectedAt = modelKeyRejection(b.rec, d), now
		if first {
			return b.hooks.modelRejected
		}
	case strings.EqualFold(d.Event, "Stop"):
		b.hooks.forgetModelRejection()
	}
	return ""
}

// forgetModelRejection drops a rejection once the model answered, or the
// sandbox was handed a new key.
func (h *hookStats) forgetModelRejection() {
	h.modelRejected, h.modelRejectedAt = "", time.Time{}
}

// credentialEnv is the variable of the caller's environment a run takes
// the model credential of a profile template from (guide.mdx, "Choose the
// model credential"), or "" for one it does not take from one.
func credentialEnv(template string) string {
	switch template {
	case profiles.AnthropicID, profiles.OpenCodeAnthropicID, profiles.CopilotAnthropicID:
		return "ANTHROPIC_API_KEY"
	case profiles.ClaudeOAuthID:
		return "CLAUDE_CODE_OAUTH_TOKEN"
	case profiles.OpenAIID, profiles.OpenCodeOpenAIID:
		return "OPENAI_API_KEY"
	case profiles.ClaudeBedrockMantleID, profiles.CodexBedrockMantleID, profiles.OpenCodeBedrockMantleID,
		profiles.CopilotBedrockMantleID, profiles.BedrockMantleOpenAIID:
		return "AWS_BEARER_TOKEN_BEDROCK"
	case profiles.GeminiID:
		return "GEMINI_API_KEY"
	}
	return ""
}

// modelKeyRejection says who rejected sandbox rec's model credential, what
// that costs, and how a fresh key reaches the sandbox: a start hands it the
// key the caller's environment holds (refreshModelCredential).
func modelKeyRejection(rec record, d HookDecision) string {
	who := firstNonEmpty(llmProviderName(rec.CredentialProfile), "the model provider")
	status := ""
	if d.ModelStatus > 0 {
		status = " (HTTP " + strconv.Itoa(d.ModelStatus) + ")"
	}
	name := "the harness"
	if spec, ok := harness.Get(rec.Harness); ok {
		name = spec.DisplayName
	}
	if rec.CredentialProfile == "" {
		// DefenseClaw shared no key: the harness logged in inside.
		return upperFirst(who) + " rejected the credential " + name + " logged in with inside the sandbox" + status +
			", so it gets no answers: log in again inside the sandbox"
	}
	key := "a fresh model key"
	if env := credentialEnv(rec.CredentialProfile); env != "" {
		key = "a fresh " + env
	}
	return upperFirst(who) + " rejected the sandbox's model credential" + status + ", so " + name + " gets no answers: put " + key +
		" in your shell, end the session (`defenseclaw sandbox stop " + rec.Name + "` for a detached run), then run `defenseclaw sandbox connect " +
		rec.Name + "` from that shell, which hands the sandbox the new key"
}
