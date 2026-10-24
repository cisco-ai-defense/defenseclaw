// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"path/filepath"
	"runtime"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
)

type instructionStartupContextKey struct{}

func withInstructionStartup(ctx context.Context, snapshot activeAgentContextSnapshot) context.Context {
	if !snapshot.startupKnown {
		return ctx
	}
	return context.WithValue(ctx, instructionStartupContextKey{}, snapshot)
}

func instructionStartupFromContext(ctx context.Context) activeAgentContextSnapshot {
	snapshot, _ := ctx.Value(instructionStartupContextKey{}).(activeAgentContextSnapshot)
	return snapshot
}

// instructionStartupFiles accepts the invoking hook's snapshot on managed
// hosts. A per-user gateway can read the same files itself. In either case,
// only files the authenticated connector reads at startup are retained.
func instructionStartupFiles(ctx context.Context, connector, cwd string) map[string]string {
	if authenticatedHookConnector(ctx) != connector || !filepath.IsAbs(cwd) || isSandboxHookRequest(ctx) {
		return nil
	}
	home := hookActiveHome(ctx)
	files, supplied := hookpaths.StartupFiles(resolvedWritesFromContext(ctx))
	if !supplied {
		if _, managed := managedHookPeerFromContext(ctx); managed {
			return nil
		}
		files = hookpaths.StartupInstructionFiles(cwd, home)
	}
	if files == nil {
		return nil
	}
	return retainedInstructionStartupFiles(connector, cwd, home, files)
}

func retainedInstructionStartupFiles(connector, cwd, home string, files map[string]string) map[string]string {
	flavor := actionfacts.PathFlavorPOSIX
	if runtime.GOOS == "windows" {
		flavor = actionfacts.PathFlavorWindows
	}
	locations := instructionLocations{
		loads: connectorInstructionLoads(connector), cwds: []string{cwd}, home: home,
	}
	retained := make(map[string]string)
	for file, identity := range files {
		if !instructionLoadLocation(file, flavor, locations) {
			continue
		}
		if normalized, ok := activeAgentInstructionPath(file, flavor); ok {
			retained[normalized] = identity
		}
	}
	return retained
}

// OpenClaw and ZeptoClaw have no SessionStart hook. Their authenticated
// inspect call is the first boundary before the agent can run a tool. Capture
// its existing instruction identities once per session, before that call.
func instructionInspectStartupFiles(ctx context.Context, connector, cwd string) map[string]string {
	if isSandboxHookRequest(ctx) || serviceAccountGatewayFromContext(ctx) {
		return nil
	}
	if _, managed := managedHookPeerFromContext(ctx); managed {
		return nil
	}
	home := hookActiveHome(ctx)
	if !filepath.IsAbs(cwd) {
		if !filepath.IsAbs(home) || home == unresolvedCallerHome {
			return nil
		}
		cwd = filepath.Join(home, ".openclaw", "workspace")
	}
	files := hookpaths.StartupInstructionFiles(cwd, home)
	if files == nil {
		return nil
	}
	return retainedInstructionStartupFiles(connector, cwd, home, files)
}

func (a *APIServer) applyInstructionInspectStartup(ctx context.Context, connector, sessionID, cwd string) activeAgentContextSnapshot {
	if a == nil || authenticatedInspectConnector(ctx) != connector {
		return activeAgentContextSnapshot{}
	}
	scope := ""
	if binding, ok := sandboxauth.FromContext(ctx); ok {
		scope = sandboxBindingScope(binding)
	}
	key, ok := validScopedActiveAgentContextKey(scope, connector, sessionID)
	if !ok {
		return activeAgentContextSnapshot{}
	}
	a.restoreInstructionLoads(key)
	if _, exists := a.activeAgentContext.sessionKey(key); exists {
		return a.activeAgentContext.snapshotKey(key)
	}
	if a.activeAgentContext.ensureStartupKey(key, instructionInspectStartupFiles(ctx, connector, cwd)) {
		a.saveInstructionLoads(key)
	}
	return a.activeAgentContext.snapshotKey(key)
}

func (a *APIServer) applyInstructionStartup(ctx context.Context, connector, sessionID, event, cwd string) activeAgentContextSnapshot {
	if a == nil || authenticatedHookConnector(ctx) != connector {
		return activeAgentContextSnapshot{}
	}
	scope := ""
	if binding, ok := sandboxauth.FromContext(ctx); ok {
		scope = sandboxBindingScope(binding)
	}
	key, ok := validScopedActiveAgentContextKey(scope, connector, sessionID)
	if !ok {
		return activeAgentContextSnapshot{}
	}
	switch canonicalEvent(event) {
	case "sessionstart", "onsessionstart", "onsessionreset", "sessioncreated":
		a.activeAgentContext.beginKey(key)
		a.activeAgentContext.setStartupKey(key, instructionStartupFiles(ctx, connector, cwd))
		a.saveInstructionLoads(key)
	case "sessionend", "onsessionend", "onsessionfinalize", "sessiondeleted":
		a.activeAgentContext.endKey(key)
		a.saveInstructionLoads(key)
	default:
		if canonicalHookLifecycleEvent(event) != "tool_start" {
			return activeAgentContextSnapshot{}
		}
		a.restoreInstructionLoads(key)
		return a.activeAgentContext.snapshotKey(key)
	}
	return activeAgentContextSnapshot{}
}
