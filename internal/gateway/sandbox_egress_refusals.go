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
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
)

// A sandbox's egress proxy refuses an HTTPS destination by answering the
// CONNECT with a 403, and clients show only that the tunnel failed ("curl:
// (56) CONNECT tunnel failed, response 403"): the JSON body that says why,
// and how the user can unblock it, never reaches the agent (#954). So the
// post-tool hook of a shell or fetch tool call carries it instead: when the
// sandbox's proxy refused CONNECTs shortly before, and the agent has not been
// told of them, the hook's answer adds a short note naming each destination,
// why it is blocked and how the user can allow it (the unblock command for
// this sandbox, when an unblock lifts it). The refusals are the sandbox
// binding's own, the one whose proxy credential made the request; nothing
// in the note tells the agent how to reach a destination another way.

// SandboxEgressRefusal is a destination a sandbox's egress proxy refused
// (SandboxIngressConfig.EgressRefusals).
type SandboxEgressRefusal struct {
	Host string
	Port int
	// Category is the proxy's reason code (webhook_catcher, admin_block, ...).
	Category string
	// What says briefly what the destination is, or why it is refused
	// ("webhook catcher").
	What string
	// Remedy says who can allow it, and how ("the user can allow it for
	// this sandbox with `defenseclaw sandbox unblock ...`").
	Remedy string
}

const (
	// sandboxEgressRefusalExtra is the audit extra key naming the refusals
	// ("host:category") a hook's answer told the agent of.
	sandboxEgressRefusalExtra = "sandbox_egress_refused"
	// sandboxEgressNoticeMaxHosts is how many refused destinations a note
	// names; it counts the rest.
	sandboxEgressNoticeMaxHosts = 3
)

// sandboxEgressNoticeEvents lists, per connector, the post-tool hook events
// whose answer carries context the model reads: Claude Code's and Codex's
// hookSpecificOutput.additionalContext, Copilot's additionalContext,
// Cursor's additional_context, Devin's hookSpecificOutput.additionalContext.
// The other harnesses' post-tool hooks have no such field (Hermes, Kiro,
// OpenCode, OpenHands, Amp, Antigravity, OmniGent), so their agents are not
// told; the user still is, by the session's live notice.
var sandboxEgressNoticeEvents = map[string][]string{
	"claudecode": {"posttooluse", "posttoolusefailure"},
	"codex":      {"posttooluse"},
	"copilot":    {"posttooluse", "posttoolusefailure"},
	"cursor":     {"posttooluse"},
	"devin":      {"posttooluse"},
}

// sandboxEgressNoticeTool reports a tool call that reaches the network
// through the egress proxy: the connector's shell tool, or a fetch tool
// (Claude Code's WebFetch, Copilot's web_fetch, an MCP server's fetch).
func sandboxEgressNoticeTool(connectorName, toolName string) bool {
	if connector.IsShellTool(connectorName, toolName) {
		return true
	}
	name := strings.ToLower(strings.TrimSpace(toolName))
	// An MCP tool is named by its server and tool (mcp__fetch__fetch,
	// fetch/fetch_url): the tool decides.
	for _, sep := range []string{"__", "/", ":"} {
		if i := strings.LastIndex(name, sep); i >= 0 {
			name = name[i+len(sep):]
		}
	}
	name = strings.NewReplacer("_", "", "-", "", ".", "").Replace(name)
	switch name {
	case "webfetch", "fetch", "fetchurl", "urlfetch", "httpfetch", "httpget", "httprequest", "httppost",
		"webupload", "uploadurl", "readwebpage", "readurlcontent":
		return true
	}
	return false
}

// addSandboxEgressRefusals adds the refusals the sandbox's egress proxy
// made shortly before a post-tool hook of a shell or fetch tool call, which
// the agent has not been told of, to the hook's additional context, and
// re-renders the harness output around it. A block or ask keeps its own
// answer (and leaves the refusals for the next call), and so does every
// other request.
func (a *APIServer) addSandboxEgressRefusals(
	ctx context.Context,
	profile connector.HookProfile,
	connectorName string,
	req agentHookRequest,
	rawBody []byte,
	payload map[string]interface{},
	resp agentHookResponse,
) agentHookResponse {
	st := a.sandboxIngressState()
	if st == nil || st.egressRefusals == nil {
		return resp
	}
	binding, ok := sandboxauth.FromContext(ctx)
	if !ok {
		return resp
	}
	if !slices.Contains(sandboxEgressNoticeEvents[binding.Connector], canonicalEvent(req.HookEventName)) ||
		!sandboxEgressNoticeTool(binding.Connector, req.ToolName) {
		return resp
	}
	switch strings.ToLower(strings.TrimSpace(resp.Action)) {
	case "block", "confirm":
		return resp
	}
	refusals := st.egressRefusals(binding)
	if len(refusals) == 0 {
		return resp
	}
	noteSandboxEgressRefusals(ctx, refusals)
	notice := sandboxEgressRefusalNotice(refusals)
	if resp.AdditionalContext != "" {
		notice = resp.AdditionalContext + "\n\n" + notice
	}
	resp.AdditionalContext = notice
	resp.HookOutput = sandboxHookOutput(ctx, profile, req, rawBody, payload, nil, resp)
	return resp
}

// sandboxEgressRefusalNotice is the agent's note of refused destinations.
func sandboxEgressRefusalNotice(refusals []SandboxEgressRefusal) string {
	if len(refusals) == 1 {
		r := refusals[0]
		connection := "connection to " + sandboxEgressTarget(r)
		if r.Port == 443 || r.Port == 0 {
			connection = "HTTPS " + connection
		}
		return "DefenseClaw's egress policy just blocked this sandbox's " + connection + " (" + r.What +
			"); a tool sees only a connection error, not the reason. " + sentence(upperFirst(r.Remedy)) +
			" Tell the user if the task needs it, and do not try to reach it another way."
	}
	var b strings.Builder
	b.WriteString("DefenseClaw's egress policy just blocked these connections from this sandbox; a tool sees only a connection error, not the reason:")
	shown := refusals[:min(len(refusals), sandboxEgressNoticeMaxHosts)]
	for _, r := range shown {
		b.WriteString("\n- " + sandboxEgressTarget(r) + " (" + r.What + "): " + sentence(r.Remedy))
	}
	if more := len(refusals) - len(shown); more > 0 {
		fmt.Fprintf(&b, "\n- and %d more", more)
	}
	b.WriteString("\nTell the user if the task needs them, and do not try to reach them another way.")
	return b.String()
}

// sandboxEgressTarget is a refused destination as the note names it: its
// host, and the port unless it is a web port.
func sandboxEgressTarget(r SandboxEgressRefusal) string {
	if r.Port == 0 || r.Port == 443 || r.Port == 80 {
		return r.Host
	}
	host := r.Host
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return host + ":" + strconv.Itoa(r.Port)
}

func upperFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// noteSandboxEgressRefusals records, for the request's audit row, the
// refusals its answer told the agent of.
func noteSandboxEgressRefusals(ctx context.Context, refusals []SandboxEgressRefusal) {
	coverage, ok := ctx.Value(sandboxCoverageContextKey{}).(*sandboxCoverage)
	if !ok {
		return
	}
	coverage.mu.Lock()
	for _, r := range refusals {
		coverage.refused = append(coverage.refused, r.Host+":"+r.Category)
	}
	coverage.mu.Unlock()
}

// sandboxEgressRefused returns what noteSandboxEgressRefusals recorded.
func sandboxEgressRefused(ctx context.Context) []string {
	coverage, ok := ctx.Value(sandboxCoverageContextKey{}).(*sandboxCoverage)
	if !ok {
		return nil
	}
	coverage.mu.Lock()
	defer coverage.mu.Unlock()
	return slices.Clone(coverage.refused)
}
