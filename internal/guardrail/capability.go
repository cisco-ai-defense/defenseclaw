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

package guardrail

import "strings"

// ToolCapabilityClass categorizes a tool call by what it can do to the
// host or the network. The correlator uses this to reason about
// capability sequences without hardcoding tool names — e.g. "execute
// a destructive capability in a session with prior credential reads"
// works whether the tool was named `run_shell`, `bash`, or anything
// else.
type ToolCapabilityClass string

const (
	CapReadFS       ToolCapabilityClass = "read_fs"
	CapWriteFS      ToolCapabilityClass = "write_fs"
	CapExecShell    ToolCapabilityClass = "exec_shell"
	CapNetworkFetch ToolCapabilityClass = "network_fetch"
	CapSendMessage  ToolCapabilityClass = "send_message"
	CapUnknown      ToolCapabilityClass = ""
)

// ClassifyToolName maps a well-known MCP tool name to its capability
// class. Unknown tools return CapUnknown; the correlator ignores
// capability for those. Conservative on purpose — we'd rather miss
// classifying an exotic tool than mis-classify and trigger a false
// CORR-DESTRUCTIVE-FLOW escalation.
func ClassifyToolName(tool string) ToolCapabilityClass {
	t := strings.ToLower(strings.TrimSpace(tool))
	switch t {
	// Filesystem reads
	case "read_file", "read-file", "fs_read", "file_read", "cat", "head", "tail", "grep":
		return CapReadFS
	// Filesystem writes
	case "write_file", "write-file", "fs_write", "file_write", "edit_file", "apply_patch":
		return CapWriteFS
	// Shell execution — the destructive class
	case "run_shell", "shell_exec", "bash", "sh", "zsh", "cmd", "powershell", "execute_command":
		return CapExecShell
	// Network fetches
	case "fetch", "http_request", "http_get", "curl", "wget", "web_fetch", "web_get":
		return CapNetworkFetch
	// Outbound messaging (email, chat, webhook)
	case "send_email", "send_message", "post_webhook", "slack_post", "teams_post":
		return CapSendMessage
	}

	// Prefix-based fallback for MCP servers that namespace their tools
	// (e.g. "shell.run", "fs.read_file"). Keeps the map above short
	// without missing obvious patterns.
	switch {
	case strings.HasPrefix(t, "shell.") || strings.HasPrefix(t, "bash.") || strings.HasSuffix(t, "_shell"):
		return CapExecShell
	case strings.HasPrefix(t, "fs.read") || strings.HasSuffix(t, "_read"):
		return CapReadFS
	case strings.HasPrefix(t, "fs.write") || strings.HasSuffix(t, "_write"):
		return CapWriteFS
	case strings.HasPrefix(t, "http.") || strings.HasPrefix(t, "net.") || strings.HasSuffix(t, "_fetch"):
		return CapNetworkFetch
	}

	return CapUnknown
}

// ruleCapabilities maps a detection rule id to the tool-capability
// class the matched behaviour represents. Findings emitted by the
// regex/plugin scanners don't carry a tool name (they match on
// content), so the correlator can't derive a capability from
// ClassifyToolName for them — this static table is the equivalent
// rule-id → capability source. Only behaviours that actually exercise
// a capability are listed; everything else stays CapUnknown so the
// DESTRUCTIVE-FLOW pattern never escalates on a bare secret or
// injection finding.
var ruleCapabilities = map[string]ToolCapabilityClass{
	// Shell / code execution (the destructive class).
	"CMD-EVAL":          CapExecShell,
	"CMD-BASH-C":        CapExecShell,
	"CMD-PYTHON-C":      CapExecShell,
	"CMD-PERL-E":        CapExecShell,
	"CMD-RUBY-E":        CapExecShell,
	"CMD-RM-RF":         CapExecShell,
	"CMD-MKFS":          CapExecShell,
	"CMD-DD-IF":         CapExecShell,
	"CMD-CHMOD-WORLD":   CapExecShell,
	"CMD-CHOWN-ROOT":    CapExecShell,
	"CMD-SUDO":          CapExecShell,
	"CMD-ETC-WRITE":     CapExecShell,
	"CMD-CRONTAB":       CapExecShell,
	"CMD-SYSTEMCTL":     CapExecShell,
	"CMD-NETCAT-LISTEN": CapExecShell,
	"CMD-SOCAT-EXEC":    CapExecShell,
	"CMD-PIPE-BASE64":   CapExecShell,
	"SRC-EVAL":          CapExecShell,
	"SRC-NEW-FUNC":      CapExecShell,
	"SRC-CHILD-PROC":    CapExecShell,
	"SRC-EXEC":          CapExecShell,
	"SRC-DENO-RUN":      CapExecShell,
	"SRC-BUN-SPAWN":     CapExecShell,

	// Outbound network fetch / listener.
	"CMD-CURL-UPLOAD":       CapNetworkFetch,
	"CMD-WGET-POST":         CapNetworkFetch,
	"CMD-PIPE-CURL":         CapNetworkFetch,
	"CMD-PIPE-WGET":         CapNetworkFetch,
	"CMD-ARCHIVE-EXFIL":     CapNetworkFetch,
	"CMD-ENCODE-EXFIL":      CapNetworkFetch,
	"CMD-WORKSPACE-ARCHIVE": CapWriteFS,
	"SRC-FETCH":             CapNetworkFetch,
	"SRC-NET-SERVER":        CapNetworkFetch,
	"SRC-HTTP-SERVER":       CapNetworkFetch,
	"SRC-WS":                CapNetworkFetch,

	// Filesystem writes.
	"SRC-FS-WRITE": CapWriteFS,
}

// CapabilityForRuleID returns the capability class a regex/plugin
// rule id represents, or CapUnknown when the rule exercises no
// capability. This is the rule-id counterpart of ClassifyToolName:
// the finding enricher uses it to populate ToolCapabilityClass on
// content-matched findings so capability-aware correlation patterns
// (DESTRUCTIVE-FLOW) can fire without a tool name.
func CapabilityForRuleID(ruleID string) ToolCapabilityClass {
	if cap, ok := ruleCapabilities[ruleID]; ok {
		return cap
	}
	// Reverse-shell families share the exec_shell class; match by
	// prefix so new CMD-REVSHELL-* variants are covered automatically.
	if strings.HasPrefix(ruleID, "CMD-REVSHELL-") {
		return CapExecShell
	}
	return CapUnknown
}
