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
	"fmt"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/enforce"
)

// mcpServerRuntimeBlock decides whether a runtime tool call must be denied
// because it belongs to an MCP server the operator has blocked via
// `defenseclaw mcp block <server>` (global) or `... --connector <c>` (scoped).
//
// This is the Go-gateway runtime enforcement point for an MCP-server block.
// Previously the gateway honored the PolicyEngine block store only for the
// `tool` target type (IsToolBlockedForConnector); an `mcp` block was written to
// the audit DB and enforced by the Python CLI / admission gate but never
// consulted when the blocked server's tools were actually invoked at Go
// runtime — a fail-open affecting BOTH global and per-connector blocks. We
// resolve the owning MCP server from the explicit hook payload field when
// present, otherwise from the tool name (`mcp__<server>__<tool>` /
// `mcp:<server>:<tool>`), and consult IsBlockedForConnector("mcp", server,
// connector), which resolves
// most-specific-wins (connector-scoped entry, then the bare global entry): a
// global block denies every connector while a `--connector` block denies only
// its peer. Mirrors the Python admission gate's is_blocked_for_connector
// consumption (cli/defenseclaw/enforce/admission.py).
//
// Security posture: fail CLOSED and degrade LOUDLY. A store lookup error
// returns deny=true with an error reason rather than silently allowing the
// call; callers must log/emit that reason so the degrade is never silent.
//
// Returns deny=false (server may still be non-empty) when the tool is not an
// MCP tool or the resolved server is not blocked.
func mcpServerRuntimeBlock(pe *enforce.PolicyEngine, toolName, connector, explicitServer string) (deny bool, server, reason string) {
	if pe == nil {
		return false, "", ""
	}
	server = strings.TrimSpace(explicitServer)
	if server == "" {
		server = serverFromMCPToolName(toolName)
	}
	if server == "" {
		return false, "", ""
	}
	blocked, err := pe.IsBlockedForConnector("mcp", server, connector)
	if err != nil {
		// Fail closed: an ambiguous / errored lookup must deny, never allow.
		return true, server, fmt.Sprintf("mcp server %q block check failed — failing closed: %v", server, err)
	}
	if blocked {
		return true, server, fmt.Sprintf("mcp server %q is blocked", server)
	}
	return false, server, ""
}
