// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"path/filepath"
	"runtime"
	"slices"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
)

// A session's instruction-file snapshot records, per directory, the
// instruction files that existed when the session first reached that
// directory: at its start for the working directory, its parents and the
// home folders, and later, before the first call that works in or writes to
// another directory is judged. A file in the snapshot is protected while it
// keeps its identity; a file the session created after reaching its
// directory is ordinary work (GAP-1363). A directory the snapshot does not
// record keeps the call-time proof: an instruction file that exists there
// now is protected (provedHighWriteFindings).

type instructionStartupContextKey struct{}

// instructionStartupView is the snapshot a call is judged with. extend adds
// the directories the call reaches first and returns the snapshot after
// that; it is nil when the gateway cannot read the caller's files itself.
type instructionStartupView struct {
	snapshot activeAgentContextSnapshot
	extend   func(dirs []string) activeAgentContextSnapshot
}

func (a *APIServer) withInstructionStartup(ctx context.Context, connector, sessionID string, snapshot activeAgentContextSnapshot) context.Context {
	if !snapshot.startupKnown {
		return ctx
	}
	view := instructionStartupView{snapshot: snapshot}
	if key, ok := instructionStartupKey(ctx, connector, sessionID); ok && instructionSelfSnapshot(ctx) {
		view.extend = func(dirs []string) activeAgentContextSnapshot {
			a.extendInstructionStartupDirs(key, dirs)
			return a.activeAgentContext.snapshotKey(key)
		}
	}
	return context.WithValue(ctx, instructionStartupContextKey{}, view)
}

func instructionStartupFromContext(ctx context.Context) instructionStartupView {
	view, _ := ctx.Value(instructionStartupContextKey{}).(instructionStartupView)
	return view
}

func instructionStartupKey(ctx context.Context, connector, sessionID string) (activeAgentContextKey, bool) {
	scope := ""
	if binding, ok := sandboxauth.FromContext(ctx); ok {
		scope = sandboxBindingScope(binding)
	}
	return validScopedActiveAgentContextKey(scope, connector, sessionID)
}

// instructionSelfSnapshot reports whether the gateway reads the caller's
// instruction files on its own file system. A sandboxed agent's files are
// the guest's; a managed hook's or a service-account gateway's caller may
// keep files the gateway cannot read, which would look absent.
func instructionSelfSnapshot(ctx context.Context) bool {
	if isSandboxHookRequest(ctx) || serviceAccountGatewayFromContext(ctx) {
		return false
	}
	_, managed := managedHookPeerFromContext(ctx)
	return !managed
}

func instructionHome(ctx context.Context) string {
	if home := hookActiveHome(ctx); filepath.IsAbs(home) && home != unresolvedCallerHome {
		return home
	}
	return ""
}

func instructionHostFlavor() actionfacts.PathFlavor {
	if runtime.GOOS == "windows" {
		return actionfacts.PathFlavorWindows
	}
	return actionfacts.PathFlavorPOSIX
}

// instructionDirectoryKey is a directory as the snapshot records it: the
// parent of an instruction file activeAgentInstructionPath normalized.
func instructionDirectoryKey(dir string) (string, bool) {
	if !filepath.IsAbs(dir) {
		return "", false
	}
	normalized, ok := activeAgentInstructionPath(filepath.Join(filepath.Clean(dir), "AGENTS.md"), instructionHostFlavor())
	if !ok {
		return "", false
	}
	return instructionParent(normalized), true
}

// instructionSnapshot normalizes the files found in dirs. It keeps only the
// names connector's agent loads somewhere: another name is never a load
// location of that agent.
func instructionSnapshot(connector string, files map[string]string, dirs []string) (map[string]string, []string) {
	names := connectorInstructionLoadNames(connector)
	var keys []string
	for _, dir := range dirs {
		if key, ok := instructionDirectoryKey(dir); ok && !slices.Contains(keys, key) {
			keys = append(keys, key)
		}
	}
	retained := make(map[string]string)
	for file, identity := range files {
		name, named := hookpaths.InstructionFileName(filepath.Base(file), runtime.GOOS == "windows")
		if !named || !slices.Contains(names, name) {
			continue
		}
		if normalized, ok := activeAgentInstructionPath(file, instructionHostFlavor()); ok &&
			slices.Contains(keys, instructionParent(normalized)) {
			retained[normalized] = identity
		}
	}
	return retained, keys
}

// instructionStartupFiles is the snapshot of an authenticated SessionStart.
// A managed hook sends the one its client read as the user; the gateway
// claims only the places that do not depend on the client's environment. A
// per-user gateway reads the same files itself.
func instructionStartupFiles(ctx context.Context, connector, cwd string) (map[string]string, []string) {
	if authenticatedHookConnector(ctx) != connector || !filepath.IsAbs(cwd) || isSandboxHookRequest(ctx) {
		return nil, nil
	}
	home := instructionHome(ctx)
	if files, supplied := hookpaths.StartupFiles(resolvedWritesFromContext(ctx)); supplied {
		return instructionSnapshot(connector, files, hookpaths.InstructionDirectories(cwd, home))
	}
	if _, managed := managedHookPeerFromContext(ctx); managed {
		return nil, nil
	}
	dirs := hookpaths.StartupDirectories(cwd, home)
	files := hookpaths.InstructionFilesIn(dirs)
	if files == nil {
		return nil, nil
	}
	return instructionSnapshot(connector, files, dirs)
}

// extendInstructionStartup adds the working directory of a running
// session's call, its parents and the home folders to the snapshot before
// the call is judged.
func (a *APIServer) extendInstructionStartup(ctx context.Context, key activeAgentContextKey, cwd string) {
	if !filepath.IsAbs(cwd) || !instructionSelfSnapshot(ctx) {
		return
	}
	a.extendInstructionStartupDirs(key, hookpaths.StartupDirectories(cwd, instructionHome(ctx)))
}

// maxReachedDirectoriesPerCall bounds the directories one call adds; the
// rest keep the call-time proof.
const maxReachedDirectoriesPerCall = 160

func (a *APIServer) extendInstructionStartupDirs(key activeAgentContextKey, dirs []string) {
	known, ok := a.activeAgentContext.startupDirsKey(key)
	if !ok {
		return
	}
	var reached, keys []string
	for _, dir := range dirs {
		dirKey, ok := instructionDirectoryKey(dir)
		if !ok || slices.Contains(known, dirKey) || slices.Contains(keys, dirKey) {
			continue
		}
		if len(reached) == maxReachedDirectoriesPerCall {
			break
		}
		keys = append(keys, dirKey)
		reached = append(reached, filepath.Clean(dir))
	}
	if len(reached) == 0 {
		return
	}
	files := hookpaths.InstructionFilesIn(reached)
	if files == nil {
		return
	}
	retained, reachedKeys := instructionSnapshot(key.connector, files, reached)
	if a.activeAgentContext.extendStartupKey(key, retained, reachedKeys) {
		a.saveInstructionLoads(key)
	}
}

// applyInstructionInspectStartup gives an authenticated inspect call its
// session's snapshot. OpenClaw and ZeptoClaw have no SessionStart hook:
// their first inspect call is the boundary before the agent can run a tool,
// so it takes the snapshot. Another connector's inspect call shares the
// snapshot its hooks took for the same session.
func (a *APIServer) applyInstructionInspectStartup(ctx context.Context, connector, sessionID, cwd string) activeAgentContextSnapshot {
	if a == nil || authenticatedInspectConnector(ctx) != canonicalConnectorRulePackKey(connector) {
		return activeAgentContextSnapshot{}
	}
	key, ok := instructionStartupKey(ctx, connector, sessionID)
	if !ok {
		return activeAgentContextSnapshot{}
	}
	a.restoreInstructionLoads(key)
	if key.connector == "openclaw" || key.connector == "zeptoclaw" {
		if !filepath.IsAbs(cwd) {
			cwd = ""
			if home := instructionHome(ctx); home != "" {
				cwd = filepath.Join(home, ".openclaw", "workspace")
			}
		}
		if _, exists := a.activeAgentContext.sessionKey(key); !exists && cwd != "" && instructionSelfSnapshot(ctx) {
			dirs := hookpaths.StartupDirectories(cwd, instructionHome(ctx))
			if files := hookpaths.InstructionFilesIn(dirs); files != nil {
				retained, keys := instructionSnapshot(key.connector, files, dirs)
				if a.activeAgentContext.ensureStartupKey(key, retained, keys) {
					a.saveInstructionLoads(key)
				}
			}
		}
	}
	a.extendInstructionStartup(ctx, key, cwd)
	return a.activeAgentContext.snapshotKey(key)
}

func (a *APIServer) applyInstructionStartup(ctx context.Context, connector, sessionID, event, cwd string) activeAgentContextSnapshot {
	if a == nil || authenticatedHookConnector(ctx) != connector {
		return activeAgentContextSnapshot{}
	}
	key, ok := instructionStartupKey(ctx, connector, sessionID)
	if !ok {
		return activeAgentContextSnapshot{}
	}
	switch canonicalEvent(event) {
	case "sessionstart", "onsessionstart", "onsessionreset", "sessioncreated":
		a.activeAgentContext.beginKey(key)
		files, dirs := instructionStartupFiles(ctx, connector, cwd)
		a.activeAgentContext.setStartupKey(key, files, dirs)
		a.saveInstructionLoads(key)
	case "sessionend", "onsessionend", "onsessionfinalize", "sessiondeleted":
		a.activeAgentContext.endKey(key)
		a.saveInstructionLoads(key)
	default:
		// Any other lifecycle event, an OpenCode session.error included,
		// leaves the snapshot as it is.
		if canonicalHookLifecycleEvent(event) != "tool_start" {
			return activeAgentContextSnapshot{}
		}
		a.restoreInstructionLoads(key)
		a.extendInstructionStartup(ctx, key, cwd)
		return a.activeAgentContext.snapshotKey(key)
	}
	return activeAgentContextSnapshot{}
}
