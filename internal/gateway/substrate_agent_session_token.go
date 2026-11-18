// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"regexp"
	"strings"
)

// agentSessionTokenNames are variables an agent creates for itself and
// exports to its own tool processes, whose value authenticates to the
// running session: Claude Code's per-session local message inbox token
// (CLAUDE_CODE_MESSAGING_TOKEN; its socket is CLAUDE_CODE_MESSAGING_SOCKET).
// DefenseClaw neither sets nor needs them. An agent that lists its
// environment puts the value into the model content the hook reports
// (substrate-1 GAP-0525).
var agentSessionTokenNames = []string{"CLAUDE_CODE_MESSAGING_TOKEN"}

// agentSessionTokenQuote are the characters around a name or a value in an
// environment listing, JSON, a shell export or a model's markdown answer
// (**`NAME`**: `value`).
const agentSessionTokenQuote = "\"'`*"

// agentSessionTokenRe is an assignment of one of them: the name, quotes, a
// colon or an equals sign, quotes, the value.
var agentSessionTokenRe = regexp.MustCompile(`(` + strings.Join(agentSessionTokenNames, "|") + `)([` + agentSessionTokenQuote + `]*\s*[:=]\s*[` +
	agentSessionTokenQuote + `]*)([^\s` + agentSessionTokenQuote + `,;)\]}]+)`)

// maskAgentSessionTokens replaces the value of every agent session token
// assignment in content with <redacted>, before the content reaches an
// audit row or an OTLP record.
func maskAgentSessionTokens(content string) string {
	for _, n := range agentSessionTokenNames {
		if strings.Contains(content, n) {
			return agentSessionTokenRe.ReplaceAllString(content, "${1}${2}<redacted>")
		}
	}
	return content
}
