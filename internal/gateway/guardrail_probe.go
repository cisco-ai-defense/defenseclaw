// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
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
// sentences are left out, wherever they sit in the text of a user turn (the
// only place OpenClaw sends them; GAP-0251). In a tool result, a system,
// developer or instructions text they are inspected like any other text. Everything else in the
// same message (a messaging-bridge banner, a time footer, an envelope, and any
// text an attacker put next to the probe) is inspected like any other text. A
// message is never skipped as a whole, whatever its length or shape, and a
// sentence that differs from the canonical wording is not a probe.

// The canonical sentences, each a regexp that matches it verbatim with any
// whitespace between words (canonicalProbeSentence in the tests builds them
// and proves they are its output). They are constants so the module-wide
// pattern check compiles them (internal/lazyregexp).
const (
	probeFollowStrictly  = `Follow\s+it\s+strictly\.`
	probeNoOldTasks      = `Do\s+not\s+infer\s+or\s+repeat\s+old\s+tasks\s+from\s+prior\s+chats\.`
	probeReplyOK         = `If\s+nothing\s+needs\s+attention,\s+reply\s+HEARTBEAT_OK`
	probeStartupSequence = `Execute\s+your\s+Session\s+Startup\s+sequence\s+now\s+-\s+read\s+the\s+required\s+files\s+before\s+responding\s+to\s+the\s+user\.`
	probeBootstrapFirst  = `If\s+BOOTSTRAP\.md\s+exists\s+in\s+the\s+provided\s+Project\s+Context,\s+read\s+it\s+and\s+follow\s+its\s+instructions\s+first\.`
	probeGreet           = `Then\s+greet\s+the\s+user\s+in\s+your\s+configured\s+persona,\s+if\s+one\s+is\s+provided\.`
	probeBeYourself      = `Be\s+yourself\s+-\s+use\s+your\s+defined\s+voice,\s+mannerisms,\s+and\s+mood\.`
	probeKeepShort       = `Keep\s+it\s+to\s+1-3\s+sentences\s+and\s+ask\s+what\s+they\s+want\s+to\s+do\.`
	probeDefaultModel    = `If\s+the\s+runtime\s+model\s+differs\s+from\s+default_model\s+in\s+the\s+system\s+prompt,\s+mention\s+the\s+default\s+model\.`
	probeNoInternals     = `Do\s+not\s+mention\s+internal\s+steps,\s+files,\s+tools,\s+or\s+reasoning\.`
)

// heartbeatProbeRe is OpenClaw's heartbeat prompt, in any case. Each optional
// sentence is one of its canonical sentences, in its canonical place.
var heartbeatProbeRe = lazyregexp.New(`(?i)\bRead\s+HEARTBEAT\.md` +
	`(?:\s+if\s+it\s+exists)?(?:\s*\(workspace\s+context\))?\s*\.` +
	`(?:\s+` + probeFollowStrictly + `)?` +
	`(?:\s+` + probeNoOldTasks + `)?` +
	`\s+` + probeReplyOK + `\b\.?`)

// sessionStartupProbeRe is OpenClaw's /new and /reset prompt
// (BARE_SESSION_RESET_PROMPT_BASE), in any case: its anchor sentence, in
// either variant, and then any of its canonical sentences in order.
var sessionStartupProbeRe = lazyregexp.New(`(?i)\bA\s+new\s+session\s+was\s+started\s+via\s+/new\s+or\s+/reset` +
	`(?:\.|\s+while\s+bootstrap\s+is\s+still\s+pending\s+for\s+this\s+workspace\.)` +
	`(?:\s+` + probeStartupSequence + `)?` +
	`(?:\s+` + probeBootstrapFirst + `)?` +
	`(?:\s+` + probeGreet + `)?` +
	`(?:\s+` + probeBeYourself + `)?` +
	`(?:\s+` + probeKeepShort + `)?` +
	`(?:\s+` + probeDefaultModel + `)?` +
	`(?:\s+` + probeNoInternals + `)?`)

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

// probeFreeMessages is messages with the canonical probes left out of the
// text of their user turns, for the inspectors that read the messages
// instead of the joined text. OpenClaw sends the probes as user turns only;
// a system, developer, assistant or tool message keeps them (GAP-0251).
func probeFreeMessages(msgs []ChatMessage) []ChatMessage {
	var out []ChatMessage
	for i, m := range msgs {
		if !strings.EqualFold(m.Role, "user") {
			continue
		}
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
