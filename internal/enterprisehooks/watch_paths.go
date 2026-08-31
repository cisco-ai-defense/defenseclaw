// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// WatchDirs returns the existing user-owned directories that a privileged
// enterprise guardian should watch for tamper/repair events. It performs the
// same trust checks as Install, but it does not create or modify files.
func WatchDirs(opts InstallOptions) ([]string, error) {
	if dirs, handled, err := platformWatchDirs(opts); handled {
		return dirs, err
	}
	home, err := validateUserHome(opts.UserHome)
	if err != nil {
		return nil, err
	}
	uid, _, err := resolveOwner(home, opts.OwnerUID, opts.OwnerGID)
	if err != nil {
		return nil, err
	}
	if err := validateHomeOwner(home, uid); err != nil {
		return nil, err
	}
	dataDir := strings.TrimSpace(opts.DataDir)
	if dataDir == "" {
		dataDir = filepath.Join(home, ".defenseclaw")
	}
	dataDir, err = filepath.Abs(dataDir)
	if err != nil {
		return nil, fmt.Errorf("enterprise hooks: resolve data dir: %w", err)
	}
	if err := validateUserDataDir(home, dataDir, uid); err != nil {
		return nil, err
	}

	reg := opts.Registry
	if reg == nil {
		reg = connector.NewDefaultRegistry()
	}
	name := strings.ToLower(strings.TrimSpace(opts.ConnectorName))
	if name == "" {
		return nil, fmt.Errorf("enterprise hooks: connector is required")
	}
	conn, ok := reg.Get(name)
	if !ok {
		return nil, fmt.Errorf("enterprise hooks: unknown connector %q", name)
	}
	if connector.IsProxyConnector(conn.Name()) {
		return nil, fmt.Errorf("enterprise hooks: connector %q is proxy/plugin setup-only; per-user hook install is not supported", conn.Name())
	}
	if _, ok := conn.(connector.HookScriptOwner); !ok {
		return nil, fmt.Errorf("enterprise hooks: connector %q does not own a hook script", conn.Name())
	}
	if !connector.ConnectorSupportedOnHostOS(conn.Name()) {
		return nil, fmt.Errorf("enterprise hooks: connector %q is not supported on this host OS", conn.Name())
	}

	setupOpts := connector.SetupOpts{
		DataDir:           dataDir,
		ProxyAddr:         strings.TrimSpace(opts.ProxyAddr),
		APIAddr:           strings.TrimSpace(opts.APIAddr),
		APIToken:          strings.TrimSpace(opts.APIToken),
		Interactive:       false,
		ManagedEnterprise: true,
		WorkspaceDir:      strings.TrimSpace(opts.WorkspaceDir),
		HookFailMode:      strings.TrimSpace(opts.HookFailMode),
		GuardrailMode:     strings.TrimSpace(opts.GuardrailMode),
		HILTEnabled:       opts.HILTEnabled,
		AgentVersion:      strings.TrimSpace(opts.AgentVersion),
		HookContractID:    strings.TrimSpace(opts.HookContractID),
	}
	if setupOpts.AgentVersion == "" {
		setupOpts.AgentVersion = connector.LoadCachedAgentVersion(dataDir, conn.Name())
	}
	if setupOpts.HookContractID == "" {
		resolution := connector.ResolveHookContract(conn.Name(), setupOpts.AgentVersion)
		setupOpts.HookContractID = resolution.Contract.ContractID
	}

	dirs := map[string]struct{}{}
	addDir := func(path string) {
		path = strings.TrimSpace(path)
		if path == "" {
			return
		}
		path = filepath.Clean(path)
		if err := validateOptionalExistingUserDir(home, path, uid, "watch dir"); err != nil {
			return
		}
		dirs[path] = struct{}{}
	}
	addFileParent := func(path string) {
		path = strings.TrimSpace(path)
		if path == "" {
			return
		}
		addDir(filepath.Dir(filepath.Clean(path)))
	}

	err = connector.WithUserHomeDir(home, func() error {
		for _, path := range connector.HookConfigPathsForConnector(conn, setupOpts) {
			addFileParent(path)
		}
		footprint := connector.AgentPaths{}
		if ap, ok := conn.(connector.AgentPathProvider); ok {
			footprint = ap.AgentPaths(setupOpts)
		}
		for _, path := range footprint.PatchedFiles {
			addFileParent(path)
		}
		for _, path := range footprint.BackupFiles {
			addFileParent(path)
		}
		for _, path := range footprint.HookScripts {
			addFileParent(path)
		}
		for _, path := range footprint.GeneratedFiles {
			addFileParent(path)
		}
		for _, path := range footprint.GeneratedExecutables {
			addFileParent(path)
		}
		sidecarFiles, sidecarErr := hookSidecarFiles(dataDir, conn.Name())
		if sidecarErr != nil {
			return sidecarErr
		}
		for _, path := range sidecarFiles {
			addFileParent(path)
		}
		for _, path := range footprint.CreatedDirs {
			addDir(path)
		}
		addDir(dataDir)
		addDir(filepath.Join(dataDir, "hooks"))
		return nil
	})
	if err != nil {
		return nil, err
	}
	return sortedMapKeys(dirs), nil
}

// WatchOwnership splits per-target owned files into two sets by
// expected writer, so the watch loop can react appropriately to each
// class of event.
//
//	ExclusiveWriter files are ones only DefenseClaw ever writes to:
//	  connector-specific and shared contract-digested hook scripts,
//	  _hardening.sh, .hook-<connector>.token sidecars, backup archives,
//	  generated executables. ANY event on these (Write, Chmod, Remove,
//	  Rename) is a real signal — either user tampering or the guardian's
//	  own reconcile tail, both worth acting on.
//
//	SharedWriter files are ones the agent itself writes to during
//	  normal use in addition to DefenseClaw's patches:
//	  ~/.codex/config.toml (Codex updates MRU model, plugin state,
//	  session prefs), ~/.claude/settings.json (Claude Code writes
//	  project-scoped settings), ~/.cursor/hooks.json (Cursor rewrites
//	  for extensions). Write and Chmod on these are almost always
//	  the agent updating its own state, NOT a tamper — so we react
//	  only to Create, Remove, and Rename, and let the 5-min backstop
//	  reconcile catch any pathological in-place rewrite. Create is
//	  included because Linux reports rename-into-place as Create.
//
// The rationale: without this split, every session Codex opens will
// touch config.toml, fire an fsnotify Write, pass the ownership
// filter, and trigger a reconcile even though the DefenseClaw entries
// in the file are untouched. The reconcile returns no_change=true
// each time but still produces log spam.
type WatchOwnership struct {
	ExclusiveWriter []string // DC-only writers; react to any event
	SharedWriter    []string // agent + DC writers; react only to Create/Remove/Rename
}

// WatchOwnedFiles returns the specific files (NOT parent directories)
// that this guardian target owns and cares about for tamper detection,
// classified by expected writer. See WatchOwnership for the two
// categories and their reaction policies.
//
// This exists because fsnotify on macOS reports directory-level
// events: watching ~/.codex/ to see config.toml also sees every
// session log, sqlite WAL rotation, and history-line append.
// Filtering by owned file path drops the majority of that noise, and
// classifying by writer drops the rest of it (agent-updates-its-own-
// config traffic).
//
// The set intentionally lists concrete files, not glob patterns —
// every artifact DefenseClaw's Install() writes has a stable path.
// If Install() ever grows a new artifact, it must be added here or
// tampering with it won't fire a repair (guarded by the reconciler
// test that installs + tampers + expects repair).
func WatchOwnedFiles(opts InstallOptions) (WatchOwnership, error) {
	if ownership, handled, err := platformWatchOwnedFiles(opts); handled {
		return ownership, err
	}
	home, err := validateUserHome(opts.UserHome)
	if err != nil {
		return WatchOwnership{}, err
	}
	uid, _, err := resolveOwner(home, opts.OwnerUID, opts.OwnerGID)
	if err != nil {
		return WatchOwnership{}, err
	}
	if err := validateHomeOwner(home, uid); err != nil {
		return WatchOwnership{}, err
	}
	dataDir := strings.TrimSpace(opts.DataDir)
	if dataDir == "" {
		dataDir = filepath.Join(home, ".defenseclaw")
	}
	dataDir, err = filepath.Abs(dataDir)
	if err != nil {
		return WatchOwnership{}, fmt.Errorf("enterprise hooks: resolve data dir: %w", err)
	}
	reg := opts.Registry
	if reg == nil {
		reg = connector.NewDefaultRegistry()
	}
	name := strings.ToLower(strings.TrimSpace(opts.ConnectorName))
	if name == "" {
		return WatchOwnership{}, fmt.Errorf("enterprise hooks: connector is required")
	}
	conn, ok := reg.Get(name)
	if !ok {
		return WatchOwnership{}, fmt.Errorf("enterprise hooks: unknown connector %q", name)
	}
	if connector.IsProxyConnector(conn.Name()) {
		return WatchOwnership{}, fmt.Errorf("enterprise hooks: connector %q is proxy/plugin setup-only", conn.Name())
	}
	if _, ok := conn.(connector.HookScriptOwner); !ok {
		return WatchOwnership{}, fmt.Errorf("enterprise hooks: connector %q does not own a hook script", conn.Name())
	}

	setupOpts := connector.SetupOpts{
		DataDir:           dataDir,
		ProxyAddr:         strings.TrimSpace(opts.ProxyAddr),
		APIAddr:           strings.TrimSpace(opts.APIAddr),
		APIToken:          strings.TrimSpace(opts.APIToken),
		Interactive:       false,
		ManagedEnterprise: true,
		WorkspaceDir:      strings.TrimSpace(opts.WorkspaceDir),
		HookFailMode:      strings.TrimSpace(opts.HookFailMode),
		GuardrailMode:     strings.TrimSpace(opts.GuardrailMode),
		HILTEnabled:       opts.HILTEnabled,
		AgentVersion:      strings.TrimSpace(opts.AgentVersion),
		HookContractID:    strings.TrimSpace(opts.HookContractID),
	}
	if setupOpts.AgentVersion == "" {
		setupOpts.AgentVersion = connector.LoadCachedAgentVersion(dataDir, conn.Name())
	}
	if setupOpts.HookContractID == "" {
		resolution := connector.ResolveHookContract(conn.Name(), setupOpts.AgentVersion)
		setupOpts.HookContractID = resolution.Contract.ContractID
	}

	managedPluginArtifacts := map[string]struct{}{}
	exclusive := map[string]struct{}{}
	shared := map[string]struct{}{}
	addExclusive := func(path string) {
		path = strings.TrimSpace(path)
		if path == "" {
			return
		}
		path = filepath.Clean(path)
		exclusive[path] = struct{}{}
		delete(shared, path)
	}
	addShared := func(path string) {
		path = strings.TrimSpace(path)
		if path == "" {
			return
		}
		path = filepath.Clean(path)
		if _, exclusiveWriter := exclusive[path]; exclusiveWriter {
			return
		}
		shared[path] = struct{}{}
	}

	err = connector.WithUserHomeDir(home, func() error {
		for _, artifact := range connector.ManagedPluginArtifacts(conn, setupOpts) {
			if artifact = strings.TrimSpace(artifact); artifact != "" {
				managedPluginArtifacts[filepath.Clean(artifact)] = struct{}{}
			}
		}
		// SHARED-WRITER: the native hook config file (codex
		// config.toml / claudecode settings.json / cursor hooks.json).
		// The agent itself writes to this constantly during normal use
		// (MRU model, plugin state, session prefs), so we ONLY react
		// to Create/Remove/Rename here. Any in-place stripping via
		// `sed -i` is caught by the 5-min backstop reconcile.
		for _, path := range connector.HookConfigPathsForConnector(conn, setupOpts) {
			if _, managedPlugin := managedPluginArtifacts[filepath.Clean(path)]; managedPlugin {
				addExclusive(path)
			} else {
				addShared(path)
			}
		}
		footprint := connector.AgentPaths{}
		if ap, ok := conn.(connector.AgentPathProvider); ok {
			footprint = ap.AgentPaths(setupOpts)
		}
		// PatchedFiles are typically the same as HookConfigPaths — the
		// agent's own config file — so they are shared-writer too.
		for _, p := range footprint.PatchedFiles {
			if _, managedPlugin := managedPluginArtifacts[filepath.Clean(p)]; managedPlugin {
				addExclusive(p)
			} else {
				addShared(p)
			}
		}
		// EXCLUSIVE-WRITER: everything below. Only DefenseClaw writes
		// to these paths, so any event is meaningful and worth acting
		// on (either user tamper or our own reconcile tail; both are
		// correctly handled by the settle window).
		for _, p := range footprint.BackupFiles {
			addExclusive(p)
		}
		// HookScripts contains BOTH the connector-specific hook
		// (codex-hook.sh / claude-code-hook.sh / cursor-hook.sh) AND
		// the four generic inspect-*.sh scripts shared across every
		// connector. The shared scripts are rendered exclusively from
		// install-wide inputs, so repeated connector installs produce
		// identical bytes and the atomic writer is a no-op. They are
		// also covered by shared_hook_script_digests in the authenticated
		// contract lock. Treat all of them as DefenseClaw-only files so
		// an in-place Write reaches the repair path; the settle/debounce
		// guards continue to absorb DefenseClaw's own publication tail.
		for _, p := range footprint.HookScripts {
			addExclusive(p)
		}
		for _, p := range footprint.GeneratedFiles {
			addExclusive(p)
		}
		for _, p := range footprint.GeneratedExecutables {
			addExclusive(p)
		}
		// Hook sidecars: the .token / .hookcfg / _hardening.sh files
		// under ~/.defenseclaw/hooks/. The connector-scoped token and
		// _hardening.sh are stable DefenseClaw-only artifacts. The
		// latter is part of shared_hook_script_digests and must react to
		// in-place writes just like the inspect scripts. The merged
		// .hookcfg and unused legacy .token remain excluded because
		// they are not stable connector-scoped files.
		sharedSidecars := map[string]struct{}{
			".token":   {},
			".hookcfg": {},
		}
		sidecarFiles, sidecarErr := hookSidecarFiles(dataDir, conn.Name())
		if sidecarErr != nil {
			return sidecarErr
		}
		for _, p := range sidecarFiles {
			if _, isShared := sharedSidecars[filepath.Base(p)]; isShared {
				continue
			}
			addExclusive(p)
		}
		return nil
	})
	if err != nil {
		return WatchOwnership{}, err
	}
	return WatchOwnership{
		ExclusiveWriter: sortedMapKeys(exclusive),
		SharedWriter:    sortedMapKeys(shared),
	}, nil
}

func sortedMapKeys(values map[string]struct{}) []string {
	out := make([]string, 0, len(values))
	for v := range values {
		out = append(out, v)
	}
	return sortedUnique(out)
}
