// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type perUserLauncherState struct {
	SchemaVersion int    `json:"schema_version"`
	InstallKind   string `json:"install_kind"`
	InstallScope  string `json:"install_scope"`
	DataRoot      string `json:"data_root"`
}

func perUserLauncherPath(executable string) bool {
	bin := filepath.Dir(executable)
	return strings.EqualFold(filepath.Base(executable), "defenseclaw.exe") &&
		strings.EqualFold(filepath.Base(bin), "bin") &&
		strings.EqualFold(filepath.Base(filepath.Dir(bin)), ".local")
}

// perUserLauncherTarget checks the installer's recorded root before the uv
// console launcher starts. A second root can be selected by the CLI's normal
// DEFENSECLAW_HOME override. The path check observes the named entry itself.
func perUserLauncherTarget(executable string, stateData []byte, selectedRoot string, isReparse func(string) (bool, error)) (string, bool, error) {
	if !perUserLauncherPath(executable) {
		return "", false, nil
	}
	var state perUserLauncherState
	if err := json.Unmarshal(stateData, &state); err != nil {
		return "", true, fmt.Errorf("read per-user launcher state: %w", err)
	}
	if state.InstallKind != "powershell-windows" || state.InstallScope != "user" {
		return "", false, nil
	}
	if state.SchemaVersion != 1 || !filepath.IsAbs(state.DataRoot) {
		return "", true, fmt.Errorf("per-user launcher state is invalid; rerun the Windows installer")
	}
	for _, root := range []string{state.DataRoot, selectedRoot} {
		if root == "" {
			continue
		}
		root = filepath.Clean(root)
		linked, err := isReparse(root)
		if err != nil && !os.IsNotExist(err) {
			return "", true, fmt.Errorf("inspect data folder %q: %w", root, err)
		}
		if linked {
			return "", true, fmt.Errorf("data folder %q is a reparse point; restore the original non-link folder at that path and retry", root)
		}
	}
	return filepath.Join(state.DataRoot, ".venv", "Scripts", "defenseclaw.exe"), true, nil
}
