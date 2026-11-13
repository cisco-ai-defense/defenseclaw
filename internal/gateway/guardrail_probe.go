// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"regexp"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/lazyregexp"
)

// The OpenClaw probes (substrate-1 GAP-0248, GAP-0196).
//
// OpenClaw sends two fixed, system-written messages as user turns: the
// liveness probe ("Read HEARTBEAT.md ... reply HEARTBEAT_OK") and the
// session-startup prompt ("A new session was started via /new or /reset ...").
// Read alone, their imperative wording looks like a prompt injection to the
// judge, so the proxy leaves the canonical text itself out of the inspected
// text.
//
// One rule, for the body and for each message: only the exact canonical
// sentences are left out, wherever they sit in a text. Everything else in the
// same message (a messaging-bridge banner, a time footer, an envelope, and any
// text an attacker put next to the probe) is inspected like any other text. A
// message is never skipped as a whole, whatever its length or shape, and a
// sentence that differs from the canonical wording is not a probe.

// canonicalProbeRe builds a regexp from canonical sentences: the sentences
// match verbatim, with any whitespace between words, in any case.
func canonicalProbeSentence(s string) string {
	words := strings.Fields(s)
	for i, w := range words {
		words[i] = regexp.QuoteMeta(w)
	}
	return strings.Join(words, `\s+`)
}

// heartbeatProbeRe is OpenClaw's heartbeat prompt. Each optional sentence is
// one of its canonical sentences, in its canonical place.
var heartbeatProbeRe = lazyregexp.New(`(?i)\bRead\s+HEARTBEAT\.md` +
	`(?:\s+if\s+it\s+exists)?(?:\s*\(workspace\s+context\))?\s*\.` +
	`(?:\s+` + canonicalProbeSentence("Follow it strictly.") + `)?` +
	`(?:\s+` + canonicalProbeSentence("Do not infer or repeat old tasks from prior chats.") + `)?` +
	`\s+` + canonicalProbeSentence("If nothing needs attention, reply HEARTBEAT_OK") + `\b\.?`)

// sessionStartupProbeRe is OpenClaw's /new and /reset prompt
// (BARE_SESSION_RESET_PROMPT_BASE): its anchor sentence, in either variant,
// and then any of its canonical sentences in order.
var sessionStartupProbeRe = lazyregexp.New(`(?i)\bA\s+new\s+session\s+was\s+started\s+via\s+/new\s+or\s+/reset` +
	`(?:\.|\s+while\s+bootstrap\s+is\s+still\s+pending\s+for\s+this\s+workspace\.)` +
	`(?:\s+` + canonicalProbeSentence("Execute your Session Startup sequence now - read the required files before responding to the user.") + `)?` +
	`(?:\s+` + canonicalProbeSentence("If BOOTSTRAP.md exists in the provided Project Context, read it and follow its instructions first.") + `)?` +
	`(?:\s+` + canonicalProbeSentence("Then greet the user in your configured persona, if one is provided.") + `)?` +
	`(?:\s+` + canonicalProbeSentence("Be yourself - use your defined voice, mannerisms, and mood.") + `)?` +
	`(?:\s+` + canonicalProbeSentence("Keep it to 1-3 sentences and ask what they want to do.") + `)?` +
	`(?:\s+` + canonicalProbeSentence("If the runtime model differs from default_model in the system prompt, mention the default model.") + `)?` +
	`(?:\s+` + canonicalProbeSentence("Do not mention internal steps, files, tools, or reasoning.") + `)?`)

// stripCanonicalProbes returns text without the canonical heartbeat and
// session-startup sentences, and whether it held any. What is left is
// everything the proxy still inspects.
func stripCanonicalProbes(text string) (string, bool) {
	found := false
	for _, re := range []*lazyregexp.Regexp{heartbeatProbeRe, sessionStartupProbeRe} {
		if !re.MatchString(text) {
			continue
		}
		found = true
		text = re.ReplaceAllString(text, "\n")
	}
	if !found {
		return text, false
	}
	return strings.TrimSpace(text), true
}

// probeFreeMessages is messages with the canonical probes left out of their
// text, for the inspectors that read the messages instead of the joined text.
func probeFreeMessages(msgs []ChatMessage) []ChatMessage {
	var out []ChatMessage
	for i, m := range msgs {
		if rest, ok := stripCanonicalProbes(m.Content); ok {
			if out == nil {
				out = append([]ChatMessage(nil), msgs...)
			}
			out[i].Content = rest
		}
	}
	if out == nil {
		return msgs
	}
	return out
}
