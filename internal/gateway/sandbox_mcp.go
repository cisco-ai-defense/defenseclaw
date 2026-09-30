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
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enforce"
	"github.com/defenseclaw/defenseclaw/internal/openshell/manager"
)

// sandboxMCPInventory is the sandbox manager's MCP import source: the
// user's own MCP servers for a harness, as DefenseClaw's MCP inventory reads
// them (user scope only, never a project's), minus the servers DefenseClaw
// blocks. A server is blocked by its block list (a scan verdict the watcher
// acted on, or `defenseclaw mcp block`), connector-scoped or global, and by
// an MCP asset policy in action mode.
type sandboxMCPInventory struct {
	config func() *config.Config
	// policy is nil without an audit store; the block list is then empty.
	policy *enforce.PolicyEngine
	// read defaults to config.ReadUserMCPServersForConnector.
	read func(connector string) ([]config.MCPServerEntry, error)
}

var _ manager.MCPInventory = (*sandboxMCPInventory)(nil)

// SandboxMCPServers implements manager.MCPInventory.
func (i *sandboxMCPInventory) SandboxMCPServers(ctx context.Context, harness string) ([]config.MCPServerEntry, []manager.MCPSkip, error) {
	read := i.read
	if read == nil {
		read = config.ReadUserMCPServersForConnector
	}
	entries, err := read(harness)
	if err != nil {
		return nil, nil, err
	}
	var cfg *config.Config
	if i.config != nil {
		cfg = i.config()
	}
	var kept []config.MCPServerEntry
	var skipped []manager.MCPSkip
	for _, e := range entries {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		name := strings.TrimSpace(e.Name)
		if e.Bundled || name == "" {
			kept = append(kept, e)
			continue
		}
		if i.policy != nil {
			blocked, err := i.policy.IsBlockedForConnector("mcp", name, harness)
			if err != nil {
				// Fail closed: a server DefenseClaw cannot check stays out.
				skipped = append(skipped, manager.MCPSkip{Name: name, Reason: "DefenseClaw could not check its block list"})
				continue
			}
			if blocked {
				skipped = append(skipped, manager.MCPSkip{Name: name, Reason: "blocked by DefenseClaw"})
				continue
			}
		}
		if cfg != nil {
			decision := cfg.EvaluateAssetPolicy(config.AssetPolicyInput{
				TargetType: "mcp", Name: name, Connector: harness, URL: e.URL, Command: e.Command, Args: e.Args,
				Transport: e.Transport, RuntimeSurface: "sandbox",
			})
			if decision.Enabled && decision.Action == "block" {
				skipped = append(skipped, manager.MCPSkip{Name: name, Reason: "blocked by the MCP asset policy"})
				continue
			}
		}
		kept = append(kept, e)
	}
	return kept, skipped, nil
}
