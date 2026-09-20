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

package telemetry

import "strings"

const modelLabelMaxLen = 64

var modelFamilyPrefixes = []string{
	"gpt-5",
	"gpt-4o",
	"gpt-4",
	"gpt-3.5",
	"o1",
	"o3",
	"claude-3.5",
	"claude-3-7",
	"claude-3",
	"claude-4",
	"claude-opus",
	"claude-sonnet",
	"claude-haiku",
	"gemini-1.5",
	"gemini-2",
	"gemini",
	"llama-3",
	"llama-4",
	"mistral",
	"deepseek",
	"qwen",
	"grok",
	"command-r",
	"phi-3",
	"phi-4",
}

// NormalizeModelLabel projects arbitrary model identifiers onto the bounded
// family vocabulary used by the generated local-observability metric profile.
func NormalizeModelLabel(model string) string {
	m := strings.ToLower(strings.TrimSpace(model))
	if m == "" {
		return "unknown"
	}
	if len(m) > modelLabelMaxLen {
		return "other"
	}
	for _, prefix := range modelFamilyPrefixes {
		if m == prefix || strings.HasPrefix(m, prefix+"-") ||
			strings.HasPrefix(m, prefix+".") || strings.HasPrefix(m, prefix+":") {
			return prefix
		}
	}
	return "other"
}

// NormalizeGenAIProviderLabel projects provider names onto a bounded GenAI
// vocabulary while retaining the established PR #403/#412 dashboard labels.
func NormalizeGenAIProviderLabel(provider string) string {
	p := strings.ToLower(strings.TrimSpace(provider))
	if p == "" {
		return "unknown"
	}
	if len(p) > 64 {
		return "other"
	}
	switch {
	case p == "openai" || p == "codex" || strings.Contains(p, "openai"):
		return "openai"
	case p == "anthropic" || strings.Contains(p, "anthropic") || strings.Contains(p, "claude"):
		return "anthropic"
	case p == "google" || strings.Contains(p, "google") || strings.Contains(p, "gemini"):
		return "google"
	case p == "azure" || strings.Contains(p, "azure"):
		return "azure"
	case p == "bedrock" || strings.Contains(p, "bedrock"):
		return "bedrock"
	case p == "ollama" || strings.Contains(p, "ollama"):
		return "ollama"
	case p == "local" || p == "unknown":
		return p
	default:
		return "other"
	}
}

// NormalizeGenAIOperationLabel projects operation names onto the bounded
// vocabulary shared by canonical GenAI metrics and local dashboards.
func NormalizeGenAIOperationLabel(operation string) string {
	op := strings.ToLower(strings.TrimSpace(operation))
	if op == "" {
		return "unknown"
	}
	if len(op) > 64 {
		return "other"
	}
	op = strings.ReplaceAll(op, "_", "-")
	switch op {
	case "chat", "completion", "completions", "responses", "response", "generate", "generation":
		return "chat"
	case "embedding", "embeddings", "embed":
		return "embedding"
	case "tool", "tool-call", "tool-result":
		return "tool"
	case "judge", "guardrail", "moderation":
		return "judge"
	case "unknown":
		return "unknown"
	default:
		return "other"
	}
}

// NormalizeHookEventTypeLabel collapses connector-specific spellings onto the
// stable hook event vocabulary used by generated metrics.
func NormalizeHookEventTypeLabel(eventType string) string {
	canon := strings.ToLower(strings.TrimSpace(eventType))
	canon = strings.NewReplacer("_", "", "-", "", ".", "").Replace(canon)
	if canon == "" {
		return "unknown"
	}
	switch canon {
	case "prompt", "userpromptsubmit", "userpromptsubmitted", "beforesubmitprompt", "preuserprompt", "prellmcall", "beforeagent", "beforemodel":
		return "prompt"
	case "toolcall", "pretooluse", "beforetool", "beforetoolselection", "pretoolcall", "permissionrequest", "beforeshellexecution", "beforemcpexecution", "beforereadfile", "beforetabfileread", "prereadcode", "prewritecode", "preruncommand", "premcptooluse":
		return "tool_call"
	case "toolresult", "posttooluse", "posttoolusefailure", "aftertool", "posttoolcall", "postreadcode", "postwritecode", "postruncommand", "postmcptooluse", "aftershellexecution", "aftermcpexecution", "afterfileedit", "aftertabfileedit", "afteragentthought", "afteragent", "posttoolbatch":
		return "tool_result"
	case "postllmcall", "postinvocation", "postcascaderesponse", "postcascaderesponsewithtranscript", "messagedisplay", "afteragentresponse", "aftermodel":
		return "response"
	case "stop", "stopfailure", "agentstop", "sessionidle", "teammateidle":
		return "stop"
	case "subagentstart":
		return "subagent_start"
	case "subagentstop":
		return "subagent_stop"
	case "notification":
		return "notification"
	case "sessionstart", "onsessionstart", "onsessionreset", "sessioncreated":
		return "session_start"
	case "sessionend", "onsessionend", "onsessionfinalize", "sessiondeleted", "sessionerror":
		return "session_end"
	case "precompact", "postcompact", "precompress", "sessioncompacted":
		return "compact"
	default:
		return "other"
	}
}

// NormalizeMetricTextLabel bounds low-cardinality descriptive metric labels.
func NormalizeMetricTextLabel(value string) string {
	v := strings.ToLower(strings.TrimSpace(value))
	if v == "" {
		return "unknown"
	}
	if len(v) > 64 {
		return "other"
	}
	var b strings.Builder
	for _, r := range v {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '_', r == '-', r == ':':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	out := strings.Trim(b.String(), "_")
	if out == "" {
		return "other"
	}
	return out
}

// NormalizeMetricIdentityLabel preserves exact join identities while removing
// control characters that are unsafe in metric label values.
func NormalizeMetricIdentityLabel(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return "unknown"
	}
	var b strings.Builder
	for _, r := range trimmed {
		if r < 0x20 || r == 0x7f {
			b.WriteByte('_')
			continue
		}
		b.WriteRune(r)
	}
	out := strings.TrimSpace(b.String())
	if out == "" {
		return "unknown"
	}
	return out
}

// AgentPhaseCode is the durable numeric vocabulary used by Grafana state
// timelines. Existing values must never be renumbered.
func AgentPhaseCode(phase string) int {
	switch strings.ToLower(strings.TrimSpace(phase)) {
	case "session":
		return 1
	case "planning":
		return 2
	case "model":
		return 3
	case "tool":
		return 4
	case "approval":
		return 5
	case "waiting":
		return 6
	case "responding":
		return 7
	case "maintenance":
		return 8
	case "completed":
		return 9
	case "failed":
		return 10
	case "interrupted":
		return 11
	case "observed":
		return 12
	default:
		return 0
	}
}

// RuntimeMetrics is the side-effect-free process snapshot consumed by the
// generation-pinned v8 capacity adapter.
type RuntimeMetrics struct {
	Goroutines     int64
	HeapAllocBytes int64
	HeapObjects    int64
	GCPauseP99Ns   int64
	FDsOpen        int64
	UptimeSeconds  float64
}

// AIComponentConfidenceAttrs carries source facts from inventory into the
// generated v8 AI-discovery metric adapter.
type AIComponentConfidenceAttrs struct {
	Ecosystem      string
	Name           string
	Framework      string
	IdentityScore  float64
	IdentityBand   string
	PresenceScore  float64
	PresenceBand   string
	InstallCount   int
	WorkspaceCount int
	PolicyVersion  int
	DetectorCount  int
}
