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
	CapReadFS        ToolCapabilityClass = "read_fs"
	CapWriteFS       ToolCapabilityClass = "write_fs"
	CapExecShell     ToolCapabilityClass = "exec_shell"
	CapNetworkFetch  ToolCapabilityClass = "network_fetch"
	CapSendMessage   ToolCapabilityClass = "send_message"
	CapUnknown       ToolCapabilityClass = ""
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
