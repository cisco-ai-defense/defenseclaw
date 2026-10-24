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
	switch canonicalHookLifecycleEvent(event) {
	case "session_start":
		a.activeAgentContext.beginKey(key)
		a.activeAgentContext.setStartupKey(key, instructionStartupFiles(ctx, connector, cwd))
		a.saveInstructionLoads(key)
	case "session_end":
		a.activeAgentContext.endKey(key)
		a.saveInstructionLoads(key)
	case "tool_start":
		a.restoreInstructionLoads(key)
		return a.activeAgentContext.snapshotKey(key)
	}
	return activeAgentContextSnapshot{}
}
