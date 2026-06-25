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
		DataDir:        dataDir,
		ProxyAddr:      strings.TrimSpace(opts.ProxyAddr),
		APIAddr:        strings.TrimSpace(opts.APIAddr),
		APIToken:       strings.TrimSpace(opts.APIToken),
		Interactive:    false,
		WorkspaceDir:   strings.TrimSpace(opts.WorkspaceDir),
		HookFailMode:   strings.TrimSpace(opts.HookFailMode),
		HILTEnabled:    opts.HILTEnabled,
		AgentVersion:   strings.TrimSpace(opts.AgentVersion),
		HookContractID: strings.TrimSpace(opts.HookContractID),
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
		for _, path := range hookSidecarFiles(dataDir) {
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

func sortedMapKeys(values map[string]struct{}) []string {
	out := make([]string, 0, len(values))
	for v := range values {
		out = append(out, v)
	}
	return sortedUnique(out)
}
