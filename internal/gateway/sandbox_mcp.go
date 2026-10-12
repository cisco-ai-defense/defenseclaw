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
	"errors"
	"strings"
	"unicode"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enforce"
	"github.com/defenseclaw/defenseclaw/internal/openshell/manager"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

// sandboxMCPInventory is the sandbox manager's MCP import source: the
// user's own MCP servers for a harness, as DefenseClaw's MCP inventory reads
// them (user scope only, never a project's), minus the servers DefenseClaw
// blocks (judgeSandboxMCPServer).
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
		if _, text := judgeSandboxMCPServer(i.policy, cfg, harness, e); text != "" {
			skipped = append(skipped, manager.MCPSkip{Name: name, Reason: text})
			continue
		}
		kept = append(kept, e)
	}
	return kept, skipped, nil
}

// judgeSandboxMCPServer decides whether a sandbox of harness may import the
// MCP server e. A server is left out by DefenseClaw's block list (a scan
// verdict the watcher acted on, or `defenseclaw mcp block`), connector-scoped
// or global, and by an MCP asset policy block for the sandbox surface. It
// returns the sandboxrelay skip reason and the user text, both "" for a
// server that is kept. policy nil checks no block list.
func judgeSandboxMCPServer(policy *enforce.PolicyEngine, cfg *config.Config, harness string, e config.MCPServerEntry) (reason, text string) {
	name := strings.TrimSpace(e.Name)
	if policy != nil {
		blocked, err := mcpServerDenied(policy, name, harness)
		if err != nil {
			// Fail closed: a server DefenseClaw cannot check stays out.
			return sandboxrelay.MCPSkipOrganizationBlock, "DefenseClaw could not check its block list"
		}
		if blocked {
			return sandboxrelay.MCPSkipOrganizationBlock, "blocked by DefenseClaw"
		}
	}
	if cfg != nil {
		decision := cfg.EvaluateAssetPolicy(config.AssetPolicyInput{
			TargetType: "mcp", Name: name, Connector: harness, URL: e.URL, Command: e.Command, Args: e.Args,
			Transport: e.Transport, RuntimeSurface: "sandbox",
		})
		if decision.Enabled && decision.Action == "block" {
			return sandboxrelay.MCPSkipAssetPolicy, "blocked by the MCP asset policy"
		}
	}
	return "", ""
}

// sandboxMCPMaxClaims bounds the MCP servers one policy/resolve may claim.
const sandboxMCPMaxClaims = 256

// errSandboxMCPClaimsTooMany refuses a resolve that claims more servers
// than sandboxMCPMaxClaims.
var errSandboxMCPClaimsTooMany = errors.New("too many MCP servers claimed")

// sandboxMCPClaims filters the MCP servers a managed daemon claims it would
// import for connectorName (ResolveRequest.MCP) by this gateway's block
// list and asset policy: the names it may import, and those it may not with
// their reason. The claims come from the user's own configuration, so a
// claim never keeps a server the organization blocks: without an audit
// store to check the block list against, every server stays out. A claim
// without a usable name is neither kept nor reported. Every claim is
// judged, a repeated name included: a name any of whose claims is left out
// is reported once with the first such reason and never kept.
func (a *APIServer) sandboxMCPClaims(ctx context.Context, connectorName string, claims []sandboxrelay.MCPServerClaim) ([]string, []sandboxrelay.MCPSkip, error) {
	if len(claims) > sandboxMCPMaxClaims {
		return nil, nil, errSandboxMCPClaimsTooMany
	}
	cfg := a.scannerCfg
	if g := a.generation(); g.published() && g.Config != nil {
		cfg = g.Config
	}
	var policy *enforce.PolicyEngine
	if a.store != nil {
		policy = enforce.NewPolicyEngine(a.store).WithConfig(func() *config.Config { return cfg })
	}
	var names []string
	reasons := make(map[string]string, len(claims))
	for _, claim := range claims {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		name := strings.TrimSpace(claim.Name)
		if !validSandboxMCPClaimName(name) {
			continue
		}
		prior, seen := reasons[name]
		if !seen {
			names = append(names, name)
		}
		if prior != "" {
			continue
		}
		reason := sandboxrelay.MCPSkipOrganizationBlock
		if policy != nil {
			entry := config.MCPServerEntry{Name: name, URL: claim.URL, Command: claim.Command, Args: claim.Args, Transport: claim.Transport}
			reason, _ = judgeSandboxMCPServer(policy, cfg, connectorName, entry)
		}
		reasons[name] = reason
	}
	kept := []string{}
	skipped := []sandboxrelay.MCPSkip{}
	for _, name := range names {
		if reason := reasons[name]; reason != "" {
			skipped = append(skipped, sandboxrelay.MCPSkip{Name: name, Reason: reason})
			continue
		}
		kept = append(kept, name)
	}
	return kept, skipped, nil
}

// validSandboxMCPClaimName accepts an MCP server name of at most 128 bytes
// without control characters.
func validSandboxMCPClaimName(name string) bool {
	if name == "" || len(name) > 128 {
		return false
	}
	return strings.IndexFunc(name, unicode.IsControl) < 0
}
