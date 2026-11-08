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
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/enforce"
	"github.com/defenseclaw/defenseclaw/internal/watcher"
)

// mcpServerRuntimeBlock decides whether a runtime tool call must be denied
// because it belongs to a denied MCP server: asset_policy.mcp.denied (written
// by `defenseclaw mcp block <server> [--connector <c>]`) or a server the
// watcher's scan verdict runtime-disabled (the actions journal).
//
// We resolve the owning MCP server from the explicit hook payload field when
// present, otherwise from the tool name (`mcp__<server>__<tool>` /
// `mcp:<server>:<tool>`). A connector-scoped rule decides before an unscoped
// one, so a global block denies every connector while a `--connector` block
// denies only its peer. Mirrors the Python admission gate.
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
	blocked, err := mcpServerDenied(pe, server, connector)
	if err != nil {
		// Fail closed: an ambiguous / errored lookup must deny, never allow.
		return true, server, fmt.Sprintf("mcp server %q block check failed — failing closed: %v", server, err)
	}
	if blocked {
		if note := mcpRuntimeDisableNote(pe, server, connector); note != "" {
			return true, server, note
		}
		return true, server, fmt.Sprintf("mcp server %q is blocked", server)
	}
	return false, server, ""
}

// mcpRuntimeDisableNote says that a server is refused because its install
// admission rejected it (a scan that failed or found a blocking finding), with
// the journal's reason. A bare "is blocked" next to an asset-policy row that
// allows the server in mode observe read as asset_policy blocking it
// (GAP-0963). "" for an operator block, and on Secure Client, which keeps the
// message of main (issue #1092).
func mcpRuntimeDisableNote(pe *enforce.PolicyEngine, server, connector string) string {
	if pe.SecureClient() {
		return ""
	}
	if operator, err := pe.IsMCPBlockedForConnector(server, connector); err != nil || operator {
		return ""
	}
	reason, disabled, err := pe.RuntimeDisableReason("mcp", server, connector)
	if err != nil || !disabled {
		return ""
	}
	note := fmt.Sprintf("mcp server %q is disabled because its install admission rejected it", server)
	if reason = strings.TrimSpace(reason); reason != "" {
		note += " (" + reason + ")"
	}
	return note + "; asset_policy.mode does not apply to admission verdicts"
}

// mcpServerDenied reports an operator block (asset_policy.mcp.denied) or a
// scan-verdict runtime disable (journal) of server for connector.
func mcpServerDenied(pe *enforce.PolicyEngine, server, connector string) (bool, error) {
	blocked, err := pe.IsMCPBlockedForConnector(server, connector)
	if err != nil || blocked {
		return blocked, err
	}
	return pe.IsDisabledForConnector("mcp", server, connector)
}

// mcpAccountRuntimeBlock refuses the tool call of an enrolled account's MCP
// server that its own admission rejected or could not scan. A managed
// gateway journals such a server under its account key
// (watcher.MCPJournalName: name, connector, account home and project) and its
// own target type (watcher.AccountMCPJournalType), not under the bare name of
// the "mcp" type, so the verdict of one account's server never refuses
// another account's server of the same name, and the rescan of one never
// releases the other (GAP-0216). The caller's home and working folder pick
// the rows; a caller whose home is not known is matched against every
// account's row of that name, and a lookup error refuses (fail closed). The
// bare-name rows, operator blocks included, stay with mcpServerRuntimeBlock.
// Secure Client has no enrolled accounts and keeps main (issue #1092).
func (a *APIServer) mcpAccountRuntimeBlock(ctx context.Context, pe *enforce.PolicyEngine, req *ToolInspectRequest) (bool, string) {
	if a == nil || a.store == nil || pe == nil || req == nil || pe.SecureClient() {
		return false, ""
	}
	server := strings.TrimSpace(req.MCPServerName)
	if server == "" {
		server = serverFromMCPToolName(req.Tool)
	}
	if server == "" {
		return false, ""
	}
	rows, err := a.store.ListActionsByType(watcher.AccountMCPJournalType)
	if err != nil {
		return true, fmt.Sprintf("mcp server %q block check failed — failing closed: %v", server, err)
	}
	home, _ := callerHomeForAssets(ctx)
	for _, row := range rows {
		if !watcher.MCPAccountRuntimeDisabled(row) {
			continue
		}
		connector := strings.ToLower(strings.TrimSpace(req.Connector))
		if connector == "" {
			connector = row.Connector // no connector named: every connector's row applies
		} else if row.Connector != "" && !strings.EqualFold(row.Connector, connector) {
			continue
		}
		query := watcher.MCPAdmissionQuery{Connector: connector, Server: server, Home: home, CWD: req.callerCWD}
		if !watcher.MCPAccountJournalServes(row.TargetName, query) {
			continue
		}
		note := fmt.Sprintf("mcp server %q is disabled because its install admission rejected it", server)
		if reason := strings.TrimSpace(row.Reason); reason != "" {
			note += " (" + reason + ")"
		}
		return true, note + "; asset_policy.mode does not apply to admission verdicts"
	}
	return false, ""
}
