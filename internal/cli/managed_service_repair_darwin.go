//go:build darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"

	"golang.org/x/sys/unix"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/observability/redaction"
)

// On macOS a deterministic config failure would otherwise exit into a
// launchd KeepAlive restart loop, so the Secure Client services start
// degraded instead. A standalone service keeps exiting on it, as before: its
// lifecycle reads the failure from the service.
func managedServiceRetriesConfigLoadPlatform() bool { return !managed.StandaloneTrustScope() }

// repairManagedServicePathsBeforeConfigLoadPlatform re-stamps the managed
// paths a service needs before config.yaml is loaded, from the fixed paths in
// its LaunchDaemon environment. The hook guardian repairs every
// DefenseClaw-owned machine object; the gateway repairs the runtime folder it
// owns. Nothing is done unless this is a root managed service.
func repairManagedServicePathsBeforeConfigLoadPlatform(role managedServiceRole) {
	layout, ok := managed.PinnedManagedServiceLayout()
	if !ok || !managed.SelfRepairEnabled() {
		return
	}
	switch role {
	case managedServiceGuardian:
		managed.RepairOwnedObjects(guardianManagedObjects(layout))
	case managedServiceGateway:
		managed.RepairOwnedObjects([]managed.OwnedObject{
			{Path: layout.RuntimeDir, Kind: managed.ObjectRuntimeDirectory, MoveAsideStructural: true, Recreate: true},
		})
	}
}

// guardianManagedObjects lists the machine objects the hook guardian owns
// and repairs, parents before children. Config, its folder and the install
// root are never moved aside: DefenseClaw cannot recreate them, so a
// structural finding there is logged and left for the strict validator.
func guardianManagedObjects(layout managed.ManagedServiceLayout) []managed.OwnedObject {
	objects := []managed.OwnedObject{
		{Path: layout.Home, Kind: managed.ObjectServiceInstallDirectory},
	}
	if layout.ConfigPath != "" {
		objects = append(objects,
			managed.OwnedObject{Path: filepath.Dir(layout.ConfigPath), Kind: managed.ObjectConfigDirectory},
			managed.OwnedObject{Path: layout.ConfigPath, Kind: managed.ObjectConfigFile},
		)
	}
	objects = append(objects,
		managed.OwnedObject{Path: layout.RuntimeDir, Kind: managed.ObjectRuntimeDirectory, MoveAsideStructural: true, Recreate: true},
		managed.OwnedObject{Path: filepath.Join(layout.RuntimeDir, hookGuardianStateFile), Kind: managed.ObjectAdminFile, MoveAsideStructural: true},
	)
	objects = append(objects, managedHookTokenObjects(layout.RuntimeDir)...)
	objects = append(objects,
		managed.OwnedObject{Path: layout.ManifestDir, Kind: managed.ObjectAdminDirectory, MoveAsideStructural: true, Recreate: true},
		managed.OwnedObject{Path: layout.ManifestPath, Kind: managed.ObjectAdminFile, MoveAsideStructural: true},
	)
	if layout.AuthorizationDir != "" {
		objects = append(objects,
			managed.OwnedObject{Path: layout.AuthorizationDir, Kind: managed.ObjectAuthorizationDirectory, MoveAsideStructural: true, Recreate: true},
			managed.OwnedObject{Path: filepath.Join(layout.AuthorizationDir, hookGuardianAuthorizationFile), Kind: managed.ObjectAdminFile, MoveAsideStructural: true},
			managed.OwnedObject{Path: filepath.Join(layout.AuthorizationDir, hookGuardianActivationFile), Kind: managed.ObjectAdminFile, MoveAsideStructural: true},
		)
	}
	return objects
}

// managedHookTokenObjects lists the runtime hooks folder and the service-side
// hook and OTLP tokens in it. A structurally wrong token is moved aside; the
// minter publishes a fresh one and the guardian re-renders the hooks.
func managedHookTokenObjects(runtimeDir string) []managed.OwnedObject {
	hooksDir := filepath.Join(runtimeDir, "hooks")
	objects := []managed.OwnedObject{
		{Path: hooksDir, Kind: managed.ObjectRuntimeDirectory, Mode: 0o700, MoveAsideStructural: true},
	}
	var tokens []string
	for _, pattern := range []string{".hook-*.token", ".otlp-*.token"} {
		matches, _ := filepath.Glob(filepath.Join(hooksDir, pattern))
		tokens = append(tokens, matches...)
	}
	sort.Strings(tokens)
	for _, token := range tokens {
		objects = append(objects, managed.OwnedObject{
			Path: token, Kind: managed.ObjectRuntimeSecretFile, Mode: 0o600, MoveAsideStructural: true,
		})
	}
	return objects
}

// repairGatewayRuntimePlatform runs in the root gateway after config load and
// before any runtime store is opened: the audit and judge-body databases and
// their SQLite side files, the redaction key, the gateway dotenv and the hook
// tokens are re-stamped on no-follow descriptors before their own strict
// validators read them. Only objects inside the pinned runtime folder are
// touched. A structurally wrong database or key is moved aside so the store
// starts fresh; the dotenv is never moved, so a token in use is not re-minted.
func repairGatewayRuntimePlatform(cfg *config.Config) {
	if cfg == nil || !managed.IsManagedEnterprise(cfg.DeploymentMode) {
		return
	}
	layout, ok := managed.PinnedManagedServiceLayout()
	if !ok || !managed.SelfRepairEnabled() {
		return
	}
	managed.RepairOwnedObjects(gatewayRuntimeObjects(cfg, layout, true))
}

// gatewayRuntimeObjects lists the gateway's runtime objects inside the pinned
// runtime folder, parents first. moveAside is false on the guardian's passes:
// the gateway holds the stores open, so a structural finding there is only
// logged and the gateway moves it aside on its next start.
func gatewayRuntimeObjects(cfg *config.Config, layout managed.ManagedServiceLayout, moveAside bool) []managed.OwnedObject {
	inside := func(path string) bool {
		return strings.TrimSpace(path) != "" && managed.ManagedServiceLayout{Home: layout.RuntimeDir}.Within(path)
	}
	var objects []managed.OwnedObject
	addDir := func(path string, mode os.FileMode) {
		if inside(path) {
			objects = append(objects, managed.OwnedObject{
				Path: path, Kind: managed.ObjectRuntimeDirectory, Mode: mode, MoveAsideStructural: moveAside, Recreate: moveAside,
			})
		}
	}
	addFile := func(path string, kind managed.ObjectKind, mode os.FileMode, moveAside bool) {
		if inside(path) {
			objects = append(objects, managed.OwnedObject{Path: path, Kind: kind, Mode: mode, MoveAsideStructural: moveAside})
		}
	}
	addDir(cfg.DataDir, 0)
	for _, db := range []string{cfg.AuditDB, cfg.JudgeBodiesDB} {
		if strings.TrimSpace(db) == "" {
			continue
		}
		if filepath.Clean(filepath.Dir(db)) != filepath.Clean(cfg.DataDir) {
			addDir(filepath.Dir(db), 0)
		}
		addFile(db, managed.ObjectRuntimeFile, 0o600, moveAside)
		for _, suffix := range []string{"-wal", "-shm", "-journal"} {
			addFile(db+suffix, managed.ObjectRuntimeFile, 0o600, moveAside)
		}
	}
	addFile(redaction.CorrelationKeyPath(cfg.DataDir), managed.ObjectRuntimeSecretFile, 0o600, moveAside)
	addFile(filepath.Join(cfg.DataDir, ".env"), managed.ObjectRuntimeSecretFile, 0o600, false)
	if inside(cfg.DataDir) {
		objects = append(objects, managedHookTokenObjects(cfg.DataDir)...)
	}
	sortOwnedObjectsParentsFirst(objects)
	return objects
}

// sortOwnedObjectsParentsFirst keeps folders ahead of what they contain.
func sortOwnedObjectsParentsFirst(objects []managed.OwnedObject) {
	sort.SliceStable(objects, func(i, j int) bool {
		if objects[i].Kind.Directory() != objects[j].Kind.Directory() {
			return objects[i].Kind.Directory()
		}
		if objects[i].Kind.Directory() {
			return strings.Count(objects[i].Path, "/") < strings.Count(objects[j].Path, "/")
		}
		return false
	})
}

// repairManagedInstallTree re-stamps the install tree's metadata: owner,
// mode, flags and ACL on bin, lib and libexec and the files directly in them.
// Content is never rewritten here; only Install re-copies code.
func repairManagedInstallTree(layout managed.ManagedServiceLayout) {
	var objects []managed.OwnedObject
	for _, name := range []string{"bin", "lib", "libexec"} {
		dir := filepath.Join(layout.Home, name)
		info, err := os.Lstat(dir)
		if err != nil {
			continue
		}
		objects = append(objects, managed.OwnedObject{Path: dir, Kind: managed.ObjectServiceInstallDirectory})
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			continue
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if !entry.Type().IsRegular() {
				continue
			}
			entryInfo, err := entry.Info()
			if err != nil {
				continue
			}
			mode := os.FileMode(0o644)
			if entryInfo.Mode().Perm()&0o111 != 0 {
				mode = 0o755
			}
			objects = append(objects, managed.OwnedObject{
				Path: filepath.Join(dir, entry.Name()), Kind: managed.ObjectInstallFile, Mode: mode,
			})
		}
	}
	managed.RepairOwnedObjects(objects)
}

// envConfigSymlinkReported keeps the env_config.json symlink finding to one
// line per streak.
var envConfigSymlinkReported atomic.Bool

// repairManagedEnvConfig handles env_config.json, which the Secure Client
// installer writes and owns. Group and other write is removed on a no-follow
// descriptor; the owner, the ACL and the content are never changed. An
// untrusted owner or writer is logged as a boundary finding.
func repairManagedEnvConfig(path string) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, unix.ELOOP) && !envConfigSymlinkReported.Swap(true) {
			managed.EmitResilienceEvent(managed.MarkerBoundary, map[string]string{
				"path":   path,
				"reason": "env_config.json is a symlink; it is not followed",
			})
		}
		return
	}
	envConfigSymlinkReported.Store(false)
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || uint32(st.Mode)&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 {
		return
	}
	if perm := uint32(st.Mode) & 0o777; perm&0o022 != 0 {
		if err := unix.Fchmod(fd, perm&^0o022); err == nil {
			managed.EmitResilienceEvent(managed.MarkerRepair, map[string]string{
				"path":   path,
				"reason": "group or other write removed from env_config.json",
			})
		}
	}
	_, _ = managed.AssessCanonical(path, managed.ObjectAdminFile, managed.CanonicalOptions{UnixMode: 0o644})
}
