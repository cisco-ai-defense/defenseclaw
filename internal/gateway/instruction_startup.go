// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"io/fs"
	"maps"
	"os"
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
// that; it is nil when the gateway cannot take a first sighting. strict is
// the call's rule pack posture: only there does an instruction file that
// merely exists now, in a directory the snapshot does not record, block.
type instructionStartupView struct {
	present  bool
	strict   bool
	snapshot activeAgentContextSnapshot
	extend   func(dirs []string) activeAgentContextSnapshot
	// lostIdentities: the session's first sighting is gone (pruned from
	// the store, or evicted unsaved); these are the identities of the
	// instruction files it had proved, so a file with one of them is still
	// the file the session found.
	lostIdentities []string
}

// existenceBlocks reports whether an instruction file proved only by
// existing now is enforced: in the strict tier, and on a path that judges
// without a view (the behaviour before the view carried the tier).
func (view instructionStartupView) existenceBlocks() bool {
	return !view.present || view.strict
}

func (a *APIServer) withInstructionStartup(ctx context.Context, connector, sessionID string, snapshot activeAgentContextSnapshot) context.Context {
	view := instructionStartupView{present: true, strict: a.instructionStrictTier(ctx, connector), snapshot: snapshot}
	if !snapshot.startupKnown {
		if key, ok := instructionStartupKey(ctx, connector, sessionID); ok {
			view.lostIdentities, _ = a.instructionFirstSightingLost(key)
		}
		return context.WithValue(ctx, instructionStartupContextKey{}, view)
	}
	if key, ok := instructionStartupKey(ctx, connector, sessionID); ok {
		if sighting, ok := instructionSightingFor(ctx, key.connector); ok {
			view.extend = func(dirs []string) activeAgentContextSnapshot {
				a.extendInstructionStartupDirs(key, dirs, sighting)
				return a.activeAgentContext.snapshotKey(key)
			}
		}
	}
	return context.WithValue(ctx, instructionStartupContextKey{}, view)
}

// instructionStrictTier reports whether connector's rule pack for the call
// (its profile's, else the configuration's) has the strict posture.
func (a *APIServer) instructionStrictTier(ctx context.Context, connector string) bool {
	cfg := a.decisionConfig(ctx)
	if cfg == nil {
		return false
	}
	ref := cfg.EffectiveRulePackRefForConnector(connector)
	return packPostureFor(cfg, ref, cfg.ResolveRulePackDir(ref)) == "strict"
}

func instructionStartupFromContext(ctx context.Context) instructionStartupView {
	view, _ := ctx.Value(instructionStartupContextKey{}).(instructionStartupView)
	return view
}

// instructionStartupKey is the key of a session's instruction-file state:
// scoped to its sandbox binding and to its verified caller, as the session
// start gate's key is (sessionStartGateKey), so two enrolled users whose
// agents use the same session ID keep separate snapshots and loads.
func instructionStartupKey(ctx context.Context, connector, sessionID string) (activeAgentContextKey, bool) {
	scope := ""
	if binding, ok := sandboxauth.FromContext(ctx); ok {
		scope = sandboxBindingScope(binding)
	}
	key, ok := validScopedActiveAgentContextKey(scope, connector, sessionID)
	if ok {
		key.caller = verifiedSessionCaller(ctx)
	}
	return key, ok
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
// more files than a snapshot does or cannot be read. reached, when set, are
// the directories the hook client read for this call: they replace the
// call's own. plain are those of them that are directories themselves, not
// links, with their identities (hookpaths.ReachedPlainDirectories).
type instructionSighting struct {
	read       func(dirs []string) (files, identities map[string]string, ok bool)
	reached    []string
	plain      map[string]string
	identities map[string]string
}

// instructionSightingFor is the gateway's own sighting when it reads the
// caller's files, and otherwise the one the managed hook client took as the
// user before the call ran (hookpaths.ReachedInstructionsKey). An OpenClaw
// or ZeptoClaw inspect call carries no client evidence: its call-time proof
// reads this host's files alone, so its sighting does too
// (readVisibleInstructionSighting). Without any of these, a directory the
// session had not reached keeps the call-time proof.
func instructionSightingFor(ctx context.Context, connector string) (instructionSighting, bool) {
	if instructionGatewayReadsFiles(ctx) {
		return instructionSighting{read: readInstructionSighting}, true
	}
	if isSandboxHookRequest(ctx) {
		return instructionSighting{}, false
	}
	facts := resolvedWritesFromContext(ctx)
	dirs, files, ok := hookpaths.ReachedInstructions(facts)
	if !ok {
		if len(facts) == 0 && (connector == "openclaw" || connector == "zeptoclaw") &&
			authenticatedInspectConnector(ctx) == canonicalConnectorRulePackKey(connector) {
			return instructionSighting{read: readVisibleInstructionSighting}, true
		}
		return instructionSighting{}, false
	}
	return instructionSighting{
		read: func([]string) (map[string]string, map[string]string, bool) {
			return files, dirs, true
		},
		reached:    slices.Sorted(maps.Keys(dirs)),
		plain:      hookpaths.ReachedPlainDirectories(facts),
		identities: dirs,
	}, true
}

// readVisibleInstructionSighting is readInstructionSighting for a gateway
// whose caller may keep files it cannot read: it reads dirs only when this
// host answers every lookup in them, so a file it is denied is never taken
// for a missing one.
func readVisibleInstructionSighting(dirs []string) (map[string]string, map[string]string, bool) {
	for _, dir := range dirs {
		if _, err := os.Stat(dir); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, nil, false
		}
		for _, name := range hookpaths.InstructionFileNames {
			if _, err := os.Stat(filepath.Join(dir, name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return nil, nil, false
			}
		}
	}
	return readInstructionSighting(dirs)
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
	withPhysicalDirectorySpellings(retained, &keys, keyed)
	return retained, keys, keyed
}

// withPhysicalDirectorySpellings records each snapshotted directory this
// host reaches through a symlinked spelling under its physical name as
// well (macOS /var and /tmp are /private/var and /private/tmp; a linked
// project), with the same files and identity: the record is keyed by the
// directory itself, so a later call or write through either spelling finds
// it (GAP-1388). A directory the host cannot resolve (behind ProtectHome)
// keeps the one spelling it was named by. Windows names are folded by
// activeAgentInstructionPath and are not resolved here.
func withPhysicalDirectorySpellings(retained map[string]string, keys *[]string, keyed map[string]string) {
	if runtime.GOOS == "windows" {
		return
	}
	for _, key := range slices.Clone(*keys) {
		physical, err := filepath.EvalSymlinks(filepath.FromSlash(key))
		if err != nil {
			continue
		}
		physicalKey, ok := instructionDirectoryKey(physical)
		if !ok || physicalKey == key || slices.Contains(*keys, physicalKey) {
			continue
		}
		*keys = append(*keys, physicalKey)
		if identity := keyed[key]; identity != "" {
			keyed[physicalKey] = identity
		}
		for _, file := range slices.Sorted(maps.Keys(retained)) {
			if instructionParent(file) == key {
				retained[strings.TrimSuffix(physicalKey, "/")+"/"+path.Base(file)] = retained[file]
			}
		}
	}
}

// instructionStartupFiles is the snapshot of an authenticated SessionStart.
// A managed hook sends the one its client read as the user; the gateway
// claims only the places that do not depend on the client's environment. A
// per-user gateway, and a managed gateway that reads the caller's files
// (instructionGatewayReadsFiles: managed Windows), reads the same files
// itself when the hook sends none, as a 1.0.3 hook does during an upgrade.
func instructionStartupFiles(ctx context.Context, connector, cwd string) (map[string]string, []string, map[string]string) {
	if authenticatedHookConnector(ctx) != connector || isSandboxHookRequest(ctx) {
		return nil, nil, nil
	}
	home := instructionHome(ctx)
	facts := resolvedWritesFromContext(ctx)
	if files, supplied := hookpaths.StartupFiles(facts); supplied {
		cwd = managedClientCWD(ctx, cwd, facts)
		if !filepath.IsAbs(cwd) {
			return nil, nil, nil
		}
		identities, reachedFiles, _ := hookpaths.ReachedInstructions(facts)
		dirs := hookpaths.InstructionDirectories(cwd, home)
		if client := startupClientCWD(cwd, facts); client != cwd {
			identities = withLocalDirectoryIdentities(identities, hookpaths.InstructionDirectories(client, home))
			dirs, files = startupClientSighting(client, home, dirs, files, identities, reachedFiles)
		}
		return instructionSnapshot(connector, files, dirs, identities)
	}
	if _, managed := managedHookPeerFromContext(ctx); managed && !instructionGatewayReadsFiles(ctx) || !filepath.IsAbs(cwd) {
		return nil, nil, nil
	}
	dirs := hookpaths.StartupDirectories(cwd, home)
	files, identities, ok := readInstructionSighting(dirs)
	if !ok {
		return nil, nil, nil
	}
	return instructionSnapshot(connector, files, dirs, identities)
}

// startupClientCWD is the directory the hook client read a startup snapshot
// in (hookpaths.CWDKey) when it spells another directory than cwd, the one
// the gateway placed the session in: the agent started in a symlinked (or
// junction, case or short-name) spelling of its project, which the gateway
// resolved to the physical directory (sanitizeHookCWD). The client's files
// are keyed by its spelling, so the snapshot is taken in that spelling
// (startupClientSighting). It is not first matched to cwd by identity:
// when the identities did not fit the hook header (GAP-1508), or the client
// named an unrelated directory, keying the client's files by cwd dropped
// every one of them and recorded cwd as holding none, so a write to the
// AGENTS.md the session started with looked like one to a file it created.
// Otherwise it is cwd.
func startupClientCWD(cwd string, facts map[string]string) string {
	client := facts[hookpaths.CWDKey]
	if !filepath.IsAbs(client) || strings.ContainsRune(client, 0) {
		return cwd
	}
	return filepath.Clean(client)
}

// withLocalDirectoryIdentities adds to the client's directory identities
// the gateway's own identity of each of dirs the client sent none for (its
// sighting did not fit the header): a gateway that can stat them carries
// the session's first record across spellings by identity
// (extendStartupKey); one that cannot (ProtectHome) adds nothing.
func withLocalDirectoryIdentities(identities map[string]string, dirs []string) map[string]string {
	out := maps.Clone(identities)
	if out == nil {
		out = make(map[string]string)
	}
	for _, dir := range dirs {
		if _, sent := out[dir]; sent {
			continue
		}
		if identity := hookpaths.DirectoryIdentity(dir); identity != "" {
			out[dir] = identity
		}
	}
	return out
}

// startupClientSighting is the startup snapshot's directories and files
// when the hook client read it in another spelling of the gateway's working
// directory (startupClientCWD): the directories the client read, in its
// spelling, with the files it found there (GAP-1493: a snapshot keyed by
// the gateway's spelling alone dropped every file the client listed, so a
// write to the AGENTS.md the session started with looked like one to a file
// it created). A directory of the gateway's spelling is recorded too when
// the client read it as well (the directory a link reaches,
// hookpaths.ReachedInstructionsKey), with the files it held then. Any
// other directory of the gateway's spelling stays out of the snapshot: the
// first call that reaches it records it, under the record of the spelling
// it has the identity of (extendStartupKey), or keeps the call-time proof.
func startupClientSighting(client, home string, gatewayDirs []string, files, identities, reachedFiles map[string]string) ([]string, map[string]string) {
	dirs := hookpaths.InstructionDirectories(client, home)
	merged := maps.Clone(files)
	for _, dir := range gatewayDirs {
		if slices.Contains(dirs, dir) {
			continue
		}
		if _, read := identities[dir]; !read {
			continue
		}
		held := 0
		for file := range reachedFiles {
			if filepath.Dir(file) == dir {
				held++
			}
		}
		if len(merged)+held > maxStartupInstructionFiles {
			continue
		}
		dirs = append(dirs, dir)
		for file, identity := range reachedFiles {
			if filepath.Dir(file) == dir {
				merged[file] = identity
			}
		}
	}
	return dirs, merged
}

// extendInstructionStartup adds the working directory of a running
// session's call, its parents and the home folders to the snapshot before
// the call is judged.
func (a *APIServer) extendInstructionStartup(ctx context.Context, key activeAgentContextKey, cwd string) {
	sighting, ok := instructionSightingFor(ctx, key.connector)
	if !ok || !filepath.IsAbs(cwd) && sighting.reached == nil {
		return
	}
	a.extendInstructionStartupDirs(key, hookpaths.StartupDirectories(cwd, instructionHome(ctx)), sighting)
}

// extendInstructionStartupDirs adds the directories of dirs the session had
// not reached to its snapshot. A session without one (its start sent no
// startup evidence, as a 1.0.3 hook's does during an upgrade, or it has no
// start hook) gets its first sighting now: a file that exists now stays
// protected, and one it creates later is its own. Existence at a later call
// never proves a file was there first.
func (a *APIServer) extendInstructionStartupDirs(key activeAgentContextKey, dirs []string, sighting instructionSighting) {
	if sighting.reached != nil {
		dirs = sighting.reached
	}
	known, unbound, ok := a.activeAgentContext.startupDirsKey(key, hookpaths.MaxReachedDirectories)
	// A recorded directory that was missing and exists now is read again
	// with this call (extendStartupKey keeps or replaces its record).
	bound, stale := sighting.bound(unbound)
	if len(bound)+len(stale) > 0 {
		known = slices.DeleteFunc(known, func(dir string) bool {
			_, rebinding := bound[dir]
			return rebinding || slices.Contains(stale, dir)
		})
		if sighting.reached == nil {
			for _, dir := range append(slices.Sorted(maps.Keys(bound)), stale...) {
				dirs = append(dirs, instructionHostDirectory(dir))
			}
		}
	}
	reached := newInstructionDirectories(dirs, known)
	var retained, keyed map[string]string
	var reachedKeys []string
	if len(reached) > 0 {
		if files, identities, read := sighting.read(reached); read {
			retained, reachedKeys, keyed = instructionSnapshot(key.connector, files, reached, identities)
		}
	}
	if !ok {
		// This host's read is a first sighting only when it sees the
		// working directory (dirs[0]); the hook client's always is.
		if sighting.reached == nil && (len(dirs) == 0 || hookpaths.DirectoryIdentity(dirs[0]) == "") {
			return
		}
		// A session whose first sighting the store pruned is not new: a
		// file that exists now may be one it created
		// (pruneInstructionLoadsLocked).
		if _, lost := a.instructionFirstSightingLost(key); lost {
			return
		}
		if len(reachedKeys) > 0 && a.activeAgentContext.firstSightingKey(key, retained, reachedKeys, keyed) {
			a.saveInstructionLoads(key)
		}
		return
	}
	if len(reachedKeys) == 0 && len(bound)+len(stale) == 0 {
		return
	}
	if a.activeAgentContext.extendStartupKey(key, retained, reachedKeys, keyed, bound, stale) {
		a.saveInstructionLoads(key)
	}
}

// newInstructionDirectories are the directories of dirs, at most
// hookpaths.MaxReachedDirectories, whose snapshot key known does not hold.
func newInstructionDirectories(dirs, known []string) []string {
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
	return reached
}

// bound is the identity each of unbound, recorded directories that were
// missing when the session first reached them, has now, when it is a
// directory itself: one the session created. stale are those that exist now
// as a link, junction or another reparse point: another spelling of a
// directory that did not start empty with the session. Both come from this
// host's file system when the gateway reads the caller's files, and
// otherwise from the hook client's sighting as the user, so a gateway that
// cannot read the user's home (ProtectHome) binds a directory the session
// created before it accepts another spelling of it.
func (s instructionSighting) bound(unbound []string) (map[string]string, []string) {
	bound, stale := boundInstructionDirectories(unbound)
	if s.reached == nil {
		return bound, stale
	}
	// The hook client's view as the user wins over this host's.
	for _, dir := range s.reached {
		key, ok := instructionDirectoryKey(dir)
		if !ok || !slices.Contains(unbound, key) {
			continue
		}
		if identity := s.plain[dir]; identity != "" {
			bound[key] = identity
			stale = slices.DeleteFunc(stale, func(recorded string) bool { return recorded == key })
		} else if s.identities[dir] != "" {
			delete(bound, key)
			if !slices.Contains(stale, key) {
				stale = append(stale, key)
			}
		}
	}
	return bound, stale
}

// instructionHostDirectory is a snapshot directory key in this host's
// spelling.
func instructionHostDirectory(dir string) string {
	host := filepath.FromSlash(dir)
	if strings.HasSuffix(dir, ":") {
		host += `\`
	}
	return host
}

// boundInstructionDirectories is instructionSighting.bound on this host's
// file system. dirs that cannot be read (another file system, a home the
// gateway cannot read) stay unbound and keep their record.
func boundInstructionDirectories(dirs []string) (map[string]string, []string) {
	bound := make(map[string]string)
	var stale []string
	for _, dir := range dirs {
		host := instructionHostDirectory(dir)
		identity := hookpaths.DirectoryIdentity(host)
		if identity == "" {
			continue
		}
		if info, err := os.Lstat(host); err == nil && info.IsDir() && info.Mode()&(os.ModeSymlink|os.ModeIrregular) == 0 {
			bound[dir] = identity
		} else {
			stale = append(stale, dir)
		}
	}
	return bound, stale
}

// applyInstructionInspectStartup gives an authenticated inspect call its
// session's snapshot. OpenClaw and ZeptoClaw have no SessionStart hook:
// their first inspect call is the boundary before the agent can run a tool,
// so it takes the snapshot, also on a service-account or managed gateway
// (readVisibleInstructionSighting). Another connector's inspect call shares the
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
	if (key.connector == "openclaw" || key.connector == "zeptoclaw") && !filepath.IsAbs(cwd) {
		cwd = ""
		if home := instructionHome(ctx); home != "" {
			cwd = filepath.Join(home, ".openclaw", "workspace")
		}
	}
	// The first inspect call of a session without a snapshot takes it
	// (extendInstructionStartupDirs).
	a.extendInstructionStartup(ctx, key, cwd)
	return a.activeAgentContext.snapshotKey(key)
}

func (a *APIServer) applyInstructionStartup(ctx context.Context, connector, sessionID, event, source, cwd string) activeAgentContextSnapshot {
	if a == nil || authenticatedHookConnector(ctx) != connector {
		return activeAgentContextSnapshot{}
	}
	key, ok := instructionStartupKey(ctx, connector, sessionID)
	if !ok {
		return activeAgentContextSnapshot{}
	}
	switch canonicalEvent(event) {
	case "sessionstart", "onsessionstart", "onsessionreset", "sessioncreated":
		a.startInstructionSession(ctx, key, event, source, cwd)
	case "sessionend", "onsessionend", "onsessionfinalize", "sessiondeleted":
		a.activeAgentContext.endKey(key)
		a.saveInstructionLoads(key)
		a.clearInstructionSightingLoss(key)
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

// startInstructionSession records a session start and its startup snapshot
// (activeAgentContextCache.startKey). A call that reached a restarted
// gateway before the late start left its record, so the record is read
// first. A reset event, or a start whose source is a resume, clear or
// compact of the session (Claude Code, Codex), always starts a new
// generation.
func (a *APIServer) startInstructionSession(ctx context.Context, key activeAgentContextKey, event, source, cwd string) {
	a.restoreInstructionLoads(key)
	newGeneration := canonicalEvent(event) == "onsessionreset"
	switch strings.ToLower(strings.TrimSpace(source)) {
	case "resume", "clear", "compact":
		newGeneration = true
	}
	files, dirs, identities := instructionStartupFiles(ctx, key.connector, cwd)
	a.activeAgentContext.startKey(key, newGeneration, files, dirs, identities)
	a.saveInstructionLoads(key)
	a.clearInstructionSightingLoss(key)
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
