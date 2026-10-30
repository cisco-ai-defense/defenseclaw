// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// Service environment the installer pins on every managed service.
const (
	enterpriseHookServiceNameEnv        = "DEFENSECLAW_WINDOWS_SERVICE_NAME"
	enterpriseHookGatewayServiceNameEnv = "DEFENSECLAW_WINDOWS_GATEWAY_SERVICE_NAME"
)

// enterpriseHookManagedInstallLayout derives the installed tree the guardian
// keeps protected from where it runs: InstallRoot is the parent of the bin
// folder holding the guardian executable, and StateRoot the parent of the
// managed data_dir (StateRoot\runtime), cross-checked against the manifest
// at StateRoot\hook-guardian\targets.yaml. Each root must sit strictly below
// the trusted Program Files or ProgramData folder, or it is left out. The IPC
// folder is fixed by the AVC contract under Program Files and is included only
// when it is this InstallRoot's own, so a side-by-side install never re-stamps
// another installation's IPC folder.
func enterpriseHookManagedInstallLayout(
	executable, dataDir, manifest, programFiles, programData string,
) (managed.ManagedInstallLayout, bool) {
	var layout managed.ManagedInstallLayout
	if strings.TrimSpace(executable) != "" && strings.TrimSpace(programFiles) != "" {
		bin := filepath.Dir(filepath.Clean(executable))
		root := filepath.Dir(bin)
		if strings.EqualFold(filepath.Base(bin), "bin") && enterpriseHookPathStrictlyBelow(root, programFiles) {
			layout.InstallRoot = root
			ipc := filepath.Join(programFiles, "Cisco", "Cisco Secure Client", "DefenseClaw", "ipc")
			if strings.EqualFold(filepath.Join(root, "ipc"), filepath.Clean(ipc)) {
				layout.IPCDirectory = filepath.Clean(ipc)
			}
		}
	}
	if strings.TrimSpace(dataDir) != "" && strings.TrimSpace(programData) != "" {
		runtimeDir := filepath.Clean(dataDir)
		stateRoot := filepath.Dir(runtimeDir)
		manifestMatches := strings.TrimSpace(manifest) == "" ||
			strings.EqualFold(filepath.Dir(filepath.Dir(filepath.Clean(manifest))), stateRoot)
		if strings.EqualFold(filepath.Base(runtimeDir), "runtime") && manifestMatches &&
			enterpriseHookPathStrictlyBelow(stateRoot, programData) {
			layout.StateRoot = stateRoot
		}
	}
	return layout, layout.InstallRoot != "" || layout.StateRoot != ""
}

// enterpriseHookPathStrictlyBelow reports whether path is a descendant of
// root, never root itself, compared case-insensitively.
func enterpriseHookPathStrictlyBelow(path, root string) bool {
	path = strings.ToLower(filepath.Clean(path))
	root = strings.ToLower(filepath.Clean(root))
	return strings.HasPrefix(path, strings.TrimSuffix(root, string(filepath.Separator))+string(filepath.Separator))
}
