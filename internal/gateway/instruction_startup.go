// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"maps"
	"path"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

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
// now is protected (provedHighWriteFindings). A directory is recorded with
// its file system identity too, so another spelling of it (a symlink, a
// case variant on a case-insensitive volume, a Windows short name) keeps
// the record of the spelling the session reached first.

type instructionStartupContextKey struct{}

// instructionStartupView is the snapshot a call is judged with. extend adds
// the directories the call reaches first and returns the snapshot after
// that; it is nil when the gateway cannot take a first sighting.
type instructionStartupView struct {
	snapshot activeAgentContextSnapshot
	extend   func(dirs []string) activeAgentContextSnapshot
}

func (a *APIServer) withInstructionStartup(ctx context.Context, connector, sessionID string, snapshot activeAgentContextSnapshot) context.Context {
	if !snapshot.startupKnown {
		return ctx
	}
	view := instructionStartupView{snapshot: snapshot}
	if key, ok := instructionStartupKey(ctx, connector, sessionID); ok {
		if sighting, ok := instructionSightingFor(ctx); ok {
			view.extend = func(dirs []string) activeAgentContextSnapshot {
				a.extendInstructionStartupDirs(key, dirs, sighting)
				return a.activeAgentContext.snapshotKey(key)
			}
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

// instructionGatewayReadsFiles reports whether the gateway reads the
// caller's instruction files on its own file system. A sandboxed agent's
// files are the guest's; a service-account gateway's and a managed POSIX
// gateway's caller may keep files the gateway cannot read (ProtectHome),
// which would look absent. A managed Windows gateway reads them: it judges
// every Windows tool call from its own reads (the managed Windows hook sends
// no tool-call evidence).
func instructionGatewayReadsFiles(ctx context.Context) bool {
	if isSandboxHookRequest(ctx) || serviceAccountGatewayFromContext(ctx) {
		return false
	}
	if _, managed := managedHookPeerFromContext(ctx); managed {
		return runtime.GOOS == "windows"
	}
	return true
}

// instructionSighting takes the first sighting of the directories a call
// reaches. read returns the instruction files of dirs and each directory's
// file system identity, keyed by the directory; ok is false when they hold
// more files than a snapshot does. reached, when set, are the directories
// the hook client read for this call: they replace the call's own.
type instructionSighting struct {
	read    func(dirs []string) (files, identities map[string]string, ok bool)
	reached []string
}

// instructionSightingFor is the gateway's own sighting when it reads the
// caller's files, and otherwise the one the managed hook client took as the
// user before the call ran (hookpaths.ReachedInstructionsKey). Without
// either, a directory the session had not reached keeps the call-time proof.
func instructionSightingFor(ctx context.Context) (instructionSighting, bool) {
	if instructionGatewayReadsFiles(ctx) {
		return instructionSighting{read: readInstructionSighting}, true
	}
	if isSandboxHookRequest(ctx) {
		return instructionSighting{}, false
	}
	dirs, files, ok := hookpaths.ReachedInstructions(resolvedWritesFromContext(ctx))
	if !ok {
		return instructionSighting{}, false
	}
	return instructionSighting{
		read: func([]string) (map[string]string, map[string]string, bool) {
			return files, dirs, true
		},
		reached: slices.Sorted(maps.Keys(dirs)),
	}, true
}

func readInstructionSighting(dirs []string) (map[string]string, map[string]string, bool) {
	files := hookpaths.InstructionFilesIn(dirs)
	if files == nil {
		return nil, nil, false
	}
	identities := make(map[string]string, len(dirs))
	for _, dir := range dirs {
		identities[dir] = hookpaths.DirectoryIdentity(dir)
	}
	return files, identities, true
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
// parent of an instruction file activeAgentInstructionPath normalized. A
// directory the saved record could not hold is not recorded.
func instructionDirectoryKey(dir string) (string, bool) {
	if !filepath.IsAbs(dir) {
		return "", false
	}
	normalized, ok := activeAgentInstructionPath(filepath.Join(filepath.Clean(dir), "AGENTS.md"), instructionHostFlavor())
	if !ok {
		return "", false
	}
	key := instructionParent(normalized)
	return key, recordedStartupDir(key)
}

// instructionSnapshot normalizes the files found in dirs and keys each
// directory's identity. It keeps only the names connector's agent loads
// somewhere: another name is never a load location of that agent.
func instructionSnapshot(connector string, files map[string]string, dirs []string, identities map[string]string) (map[string]string, []string, map[string]string) {
	names := connectorInstructionLoadNames(connector)
	var keys []string
	keyed := make(map[string]string)
	for _, dir := range dirs {
		key, ok := instructionDirectoryKey(dir)
		if !ok || slices.Contains(keys, key) {
			continue
		}
		keys = append(keys, key)
		if identity := identities[dir]; identity != "" {
			keyed[key] = identity
		}
	}
	retained := make(map[string]string)
	for file, identity := range files {
		name, named := hookpaths.InstructionFileName(filepath.Base(file), runtime.GOOS == "windows")
		if !named || !slices.Contains(names, name) {
			continue
		}
		if normalized, ok := activeAgentInstructionPath(file, instructionHostFlavor()); ok &&
			recordedStartupFile(normalized) && slices.Contains(keys, instructionParent(normalized)) {
			retained[normalized] = identity
		}
	}
	return retained, keys, keyed
}

// instructionStartupFiles is the snapshot of an authenticated SessionStart.
// A managed hook sends the one its client read as the user; the gateway
// claims only the places that do not depend on the client's environment. A
// per-user gateway reads the same files itself.
func instructionStartupFiles(ctx context.Context, connector, cwd string) (map[string]string, []string, map[string]string) {
	if authenticatedHookConnector(ctx) != connector || !filepath.IsAbs(cwd) || isSandboxHookRequest(ctx) {
		return nil, nil, nil
	}
	home := instructionHome(ctx)
	facts := resolvedWritesFromContext(ctx)
	if files, supplied := hookpaths.StartupFiles(facts); supplied {
		identities, _, _ := hookpaths.ReachedInstructions(facts)
		return instructionSnapshot(connector, files, hookpaths.InstructionDirectories(cwd, home), identities)
	}
	if _, managed := managedHookPeerFromContext(ctx); managed {
		return nil, nil, nil
	}
	dirs := hookpaths.StartupDirectories(cwd, home)
	files, identities, ok := readInstructionSighting(dirs)
	if !ok {
		return nil, nil, nil
	}
	return instructionSnapshot(connector, files, dirs, identities)
}

// extendInstructionStartup adds the working directory of a running
// session's call, its parents and the home folders to the snapshot before
// the call is judged.
func (a *APIServer) extendInstructionStartup(ctx context.Context, key activeAgentContextKey, cwd string) {
	sighting, ok := instructionSightingFor(ctx)
	if !ok || !filepath.IsAbs(cwd) && sighting.reached == nil {
		return
	}
	a.extendInstructionStartupDirs(key, hookpaths.StartupDirectories(cwd, instructionHome(ctx)), sighting)
}

func (a *APIServer) extendInstructionStartupDirs(key activeAgentContextKey, dirs []string, sighting instructionSighting) {
	known, ok := a.activeAgentContext.startupDirsKey(key)
	if !ok {
		return
	}
	if sighting.reached != nil {
		dirs = sighting.reached
	}
	var reached, keys []string
	for _, dir := range dirs {
		dirKey, ok := instructionDirectoryKey(dir)
		if !ok || slices.Contains(known, dirKey) || slices.Contains(keys, dirKey) {
			continue
		}
		if len(reached) == hookpaths.MaxReachedDirectories {
			break
		}
		keys = append(keys, dirKey)
		reached = append(reached, filepath.Clean(dir))
	}
	if len(reached) == 0 {
		return
	}
	files, identities, ok := sighting.read(reached)
	if !ok {
		return
	}
	retained, reachedKeys, keyed := instructionSnapshot(key.connector, files, reached, identities)
	if a.activeAgentContext.extendStartupKey(key, retained, reachedKeys, keyed) {
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
		if _, exists := a.activeAgentContext.sessionKey(key); !exists && cwd != "" && instructionGatewayReadsFiles(ctx) {
			dirs := hookpaths.StartupDirectories(cwd, instructionHome(ctx))
			if files, identities, ok := readInstructionSighting(dirs); ok {
				retained, keys, keyed := instructionSnapshot(key.connector, files, dirs, identities)
				if a.activeAgentContext.ensureStartupKey(key, retained, keys, keyed) {
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
		files, dirs, identities := instructionStartupFiles(ctx, connector, cwd)
		a.activeAgentContext.setStartupKey(key, files, dirs, identities)
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

// recordedStartupFile reports a snapshot file as instructionSnapshot records
// it and the saved record restores it: an absolute path of any instruction
// file name (hookpaths.InstructionFileNames, openclaw.json included), in the
// host's spelling (lower case on Windows).
func recordedStartupFile(file string) bool {
	if file == "" || len(file) > maxActiveAgentContextPathSize || strings.TrimSpace(file) != file ||
		!filepath.IsAbs(file) && !path.IsAbs(file) {
		return false
	}
	_, ok := hookpaths.InstructionFileName(path.Base(strings.ReplaceAll(file, `\`, "/")), true)
	return ok
}

// recordedStartupDir reports a snapshot directory as instructionDirectoryKey
// spells it: the parent of an instruction file, so "c:" for a Windows drive
// root.
func recordedStartupDir(dir string) bool {
	return dir != "" && (!strings.HasSuffix(dir, "/") || dir == "/") &&
		recordedStartupFile(strings.TrimSuffix(dir, "/")+"/AGENTS.md")
}

// instructionFileIn is the snapshot key of the file of base in directory, a
// key of instructionDirectoryKey.
func instructionFileIn(directory, base string) string {
	if strings.HasSuffix(directory, "/") {
		return directory + base
	}
	return directory + "/" + base
}
