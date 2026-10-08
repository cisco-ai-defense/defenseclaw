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
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
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
// credential: an authentication failure, or HTTP 401. OpenShell's refusal
// of a request that carries a credential placeholder is no rejection of the
// key, though Claude Code shows it as one (sandboxapi.ModelErrorPlaceholder).
func modelKeyRejected(d HookDecision) bool {
	return d.ModelError != sandboxapi.ModelErrorPlaceholder && (d.ModelError == "authentication_failed" || d.ModelStatus == http.StatusUnauthorized)
}

// observeModelAnswerLocked notes what a hook event says of the model API:
// a rejected credential (returned, for the feed, the first time), a turn
// that OpenShell's refusal of a credential placeholder ended (placeholder,
// the first of the session), or a turn that ended normally (Stop), which
// proves the credential works again and the conversation goes on.
func (b *box) observeModelAnswerLocked(d HookDecision, now time.Time) (rejected string, placeholder bool) {
	switch {
	case d.ModelError == sandboxapi.ModelErrorPlaceholder:
		return "", b.notePlaceholderLocked(now)
	case modelKeyRejected(d):
		first := b.hooks.modelRejectedAt.IsZero()
		b.hooks.modelRejected, b.hooks.modelRejectedAt = modelKeyRejection(b.rec, d), now
		if first {
			return b.hooks.modelRejected, false
		}
	case strings.EqualFold(d.Event, "Stop"):
		b.hooks.forgetModelRejection()
		b.hooks.placeholderAt = time.Time{}
	}
	return "", false
}

// A conversation that shows a credential placeholder (an `env` output in
// the sandbox prints them) carries it in every later request of the
// harness, to its model and in its hooks' posts, and OpenShell forwards none
// of them (sandboxapi.PlaceholderRefusal): the harness gets a 403 that reads
// like a rejected key and its hooks fail closed, while the key, the sandbox
// token and DefenseClaw are fine and a new conversation works (GAP-0354,
// GAP-0355). Such a refusal is neither a rejected key nor a hook refused by
// the sandbox's policy: the feed, the status and the session's end say what
// it is instead.

// notePlaceholderLocked records OpenShell refusing a request of b's whose
// body carried a credential placeholder, and reports whether it is the
// first of the session (since b last became ready), which the feed
// announces (placeholderFinding). Callers hold Manager.mu.
func (b *box) notePlaceholderLocked(now time.Time) bool {
	first := !b.placeholderInSessionLocked()
	b.hooks.placeholderAt = now
	b.notePlaceholderFailureLocked()
	return first
}

// placeholderFailureWindow is how close a hook failure and a refusal of a
// request that carried a credential placeholder come when the failure is a
// hook post of the conversation OpenShell refuses: OpenShell refuses the
// conversation's model request and its hook posts within a second or two.
const placeholderFailureWindow = 5 * time.Second

// notePlaceholderFailureLocked marks the last hook failure as one of a
// conversation OpenShell refuses for its credential placeholder when the
// two came within placeholderFailureWindow of each other in this session,
// whichever came first. DefenseClaw did not refuse that hook, though the
// status said "DefenseClaw answered HTTP 400" (GAP-0377), and the hooks do
// not work again while the conversation goes on (noteHookAnsweredLocked).
// Callers hold Manager.mu.
func (b *box) notePlaceholderFailureLocked() {
	failed := b.hooks.lastFailureAt
	if failed.IsZero() || failed.Before(b.started) || !b.placeholderInSessionLocked() {
		return
	}
	if d := failed.Sub(b.hooks.placeholderAt); d <= placeholderFailureWindow && d >= -placeholderFailureWindow {
		b.hooks.failureCause, b.hooks.answeredAt = sandboxapi.ReasonPlaceholderRefused, time.Time{}
	}
}

// placeholderInSessionLocked reports a placeholder refusal since b last
// became ready. Callers hold Manager.mu.
func (b *box) placeholderInSessionLocked() bool {
	return !b.hooks.placeholderAt.IsZero() && !b.hooks.placeholderAt.Before(b.started)
}

// placeholderFinding is the feed's finding for sandbox name's first
// placeholder refusal of a session.
func placeholderFinding(name string) sandboxapi.ActivityEvent {
	return sandboxapi.ActivityEvent{Kind: sandboxapi.ActivityFinding, Sandbox: name, Severity: "HIGH",
		Reason: sandboxapi.ReasonPlaceholderRefused, Message: "⚠ " + sandboxapi.PlaceholderConversationText(name)}
}

// notePlaceholderRefusal records OpenShell's refusal of a request of b's
// that carried a credential placeholder (an OCSF record).
func (m *Manager) notePlaceholderRefusal(b *box) {
	m.mu.Lock()
	first := b.sessionOn() && b.notePlaceholderLocked(m.now())
	name := b.rec.Name
	m.mu.Unlock()
	if first {
		m.feed.Publish(placeholderFinding(name))
	}
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
