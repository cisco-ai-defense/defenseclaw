// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/assetfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

type claimedAssetFactsContextKey struct{}

// withClaimedAssetFacts attaches the asset facts a standalone hook read in
// its user's home (assetfacts.Header). Only a service-account gateway,
// which cannot read that home on Linux and macOS, takes them; a per-user
// gateway reads the files itself, and Secure Client and sandbox hooks never
// send them (issue #1092).
func withClaimedAssetFacts(ctx context.Context, h http.Header) context.Context {
	if ctx == nil || ManagedEnterpriseActive() || isSandboxHookRequest(ctx) {
		return ctx
	}
	if _, peer := managedHookPeerFromContext(ctx); !peer && !serviceAccountGatewayFromContext(ctx) {
		return ctx
	}
	facts, ok := assetfacts.Decode(h.Get(assetfacts.Header))
	if !ok {
		return ctx
	}
	return context.WithValue(ctx, claimedAssetFactsContextKey{}, facts)
}

func claimedAssetFactsFromContext(ctx context.Context) assetfacts.Facts {
	if ctx == nil {
		return assetfacts.Facts{}
	}
	facts, _ := ctx.Value(claimedAssetFactsContextKey{}).(assetfacts.Facts)
	return facts
}

// callerHomeForAssets is the home of the user a service-account gateway
// answers for, when the request names one; ok is false on a per-user
// gateway, which runs as its user and reads its own home.
func callerHomeForAssets(ctx context.Context) (string, bool) {
	_, peer := managedHookPeerFromContext(ctx)
	if !peer && !serviceAccountGatewayFromContext(ctx) {
		return "", false
	}
	home := trustedActiveHome(ctx)
	if home == "" || home == unresolvedCallerHome {
		return "", true
	}
	return home, true
}

// declaredSkillNames lists the names the invoked skill declares in its
// SKILL.md, read in the caller's skill folders or, where this gateway
// cannot read them, as the standalone hook reported them. A denied rule
// matches them too, so a copy of a denied skill under another folder name is
// still refused (GAP-0570); they never admit a skill. Secure Client keeps the
// folder-name match of main (issue #1092).
func (a *APIServer) declaredSkillNames(ctx context.Context, connector, cwd string, probe skillRuntimeProbe) []string {
	if !probe.Matched || probe.RuntimeDisableOnly || runtimeSkillAssetTargetType(probe) != "skill" {
		return nil
	}
	cfg := a.liveConfig()
	if cfg == nil || cfg.SecureClientIntegration() {
		return nil
	}
	name := strings.TrimSpace(probe.SkillName)
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, `/\:`) {
		return nil
	}
	var names []string
	add := func(declared string) {
		if declared == "" || config.SameAssetName(declared, name) {
			return
		}
		for _, have := range names {
			if config.SameAssetName(have, declared) {
				return
			}
		}
		names = append(names, declared)
	}
	for _, root := range assetfacts.SkillRoots(connector, hookActiveHome(ctx), cwd) {
		add(assetfacts.DeclaredSkillName(filepath.Join(root, name)))
	}
	for _, declared := range claimedAssetFactsFromContext(ctx).DeclaredFor(name) {
		add(declared)
	}
	return names
}

// skillFolderAccessDecision blocks a tool call that reaches into the folder
// of a denied skill. Asked for a skill in plain words, Codex reads its
// SKILL.md with a shell command and follows it, and no skill selection hook
// sees that (GAP-0569). Only the denied list applies: reading any other skill
// folder is not an asset load. Secure Client keeps main (issue #1092).
func (a *APIServer) skillFolderAccessDecision(
	ctx context.Context, connector, hookEvent, cwd, toolName string, toolInput map[string]interface{},
) (config.AssetPolicyDecision, bool) {
	cfg := a.liveConfig()
	if cfg == nil || cfg.SecureClientIntegration() || len(cfg.AssetPolicy.Skill.Denied) == 0 || !runtimeAssetCanEnforce(hookEvent) {
		return config.AssetPolicyDecision{}, false
	}
	facts := claimedAssetFactsFromContext(ctx)
	for _, ref := range assetfacts.SkillFolderRefs(toolInput, hookActiveHome(ctx), cwd) {
		declared := facts.DeclaredFor(ref.Name)
		if name := assetfacts.DeclaredSkillName(ref.Dir); name != "" {
			declared = append(declared, name)
		}
		input := config.AssetPolicyInput{
			TargetType: "skill", Name: ref.Name, DeclaredNames: declared,
			Connector: connector, SourcePath: ref.Dir, RuntimeSurface: "skill_folder",
		}
		if verdict, _ := cfg.AssetListDecision(input); verdict != config.AssetListDeny {
			continue
		}
		decision := cfg.EvaluateAssetPolicy(input)
		probe := skillRuntimeProbe{
			TargetType: "skill", SkillName: ref.Name, ToolName: toolName,
			SourcePath: ref.Dir, Surface: "skill_folder", Matched: true,
		}
		a.emitRuntimeSkillAssetPolicyDecision(ctx, decision, connector, hookEvent, probe)
		return decision, true
	}
	return config.AssetPolicyDecision{}, false
}

// lookupCallerMCPServer finds the MCP server name the caller's agent has
// configured. A per-user gateway reads its own home. A service-account
// gateway reads the caller's home and, where it may not (Linux and macOS),
// takes the definition the standalone hook read as the user (GAP-0576).
func (a *APIServer) lookupCallerMCPServer(ctx context.Context, cfg *config.Config, connector, cwd, name string) (config.MCPServerEntry, bool) {
	// The agent's own command line (claude --mcp-config, codex -c) overrides
	// every file this gateway can read, so the hook's reading of it decides
	// (GAP-0954).
	if server := claimedAssetFactsFromContext(ctx).MCP; server != nil && server.Source == assetfacts.SourceCommandLine &&
		config.SameMCPToolServer(connector, server.Name, name) {
		return config.MCPServerEntry{
			Name: server.Name, URL: server.URL, Command: server.Command,
			Args: append([]string(nil), server.Args...), Transport: server.Transport,
		}, true
	}
	home, serviceAccount := callerHomeForAssets(ctx)
	if !serviceAccount {
		return cfg.LookupMCPToolServerForConnector(connector, cwd, name)
	}
	if home != "" {
		if entry, ok := config.LookupMCPServerUnderHome(connector, home, cwd, name); ok {
			return entry, true
		}
	}
	if server := claimedAssetFactsFromContext(ctx).MCP; server != nil && config.SameMCPToolServer(connector, server.Name, name) {
		return config.MCPServerEntry{
			Name: server.Name, URL: server.URL, Command: server.Command,
			Args: append([]string(nil), server.Args...), Transport: server.Transport,
		}, true
	}
	return config.MCPServerEntry{}, false
}
