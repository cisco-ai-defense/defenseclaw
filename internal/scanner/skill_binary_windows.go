//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/pathidentity"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

var skillScannerExecutable = os.Executable

// resolveDefaultSkillScanner keeps a per-user release on its pinned scanner.
// An unrelated skill-scanner.exe can shadow the installer's .cmd shim on
// Windows. Bind the native console executable to the same adjacent installer
// identity used by per-user hook recovery, including custom data roots.
func resolveDefaultSkillScanner(binary string, secureClient bool) (string, error) {
	if secureClient || managed.IsManagedEnterprise(os.Getenv(managed.DeploymentModeEnv)) ||
		(!strings.EqualFold(binary, "skill-scanner") && !strings.EqualFold(binary, "skill-scanner.exe")) {
		return binary, nil
	}
	gateway, err := skillScannerExecutable()
	if err != nil || !filepath.IsAbs(gateway) ||
		!strings.EqualFold(filepath.Base(gateway), "defenseclaw-gateway.exe") {
		return binary, nil
	}
	commandDir := filepath.Dir(gateway)
	statePath := filepath.Join(commandDir, "defenseclaw-hook-state.json")
	if _, err := os.Lstat(statePath); errors.Is(err, os.ErrNotExist) {
		// A source/development gateway has no PowerShell installer identity.
		return binary, nil
	} else if err != nil {
		return "", installedSkillScannerError(err)
	}
	// Once an installer identity is present, a broken install must not run
	// some other scanner from PATH. These readers do not repair permissions.
	if err := skillScannerPathHasNoReparsePoints(gateway); err != nil {
		return "", installedSkillScannerError(err)
	}
	if err := safefile.ValidatePrivateDirectoryOwnershipAllowingAdministrators(commandDir); err != nil {
		return "", installedSkillScannerError(err)
	}
	if err := safefile.ValidatePrivateFileOwnershipAllowingAdministrators(gateway); err != nil {
		return "", installedSkillScannerError(err)
	}
	if err := skillScannerPathHasNoReparsePoints(statePath); err != nil {
		return "", installedSkillScannerError(err)
	}
	if err := safefile.ValidatePrivateFileOwnershipAllowingAdministrators(statePath); err != nil {
		return "", installedSkillScannerError(err)
	}
	data, err := safefile.ReadRegularFileBounded(statePath, 64<<10)
	if err != nil {
		return "", installedSkillScannerError(err)
	}
	var state struct {
		SchemaVersion int    `json:"schema_version"`
		InstallKind   string `json:"install_kind"`
		InstallScope  string `json:"install_scope"`
		InstallRoot   string `json:"install_root"`
		CommandDir    string `json:"command_dir"`
		DataRoot      string `json:"data_root"`
	}
	if err := json.Unmarshal(data, &state); err != nil {
		return "", installedSkillScannerError(fmt.Errorf("invalid installer identity: %w", err))
	}
	if state.SchemaVersion != 1 || state.InstallKind != "powershell-windows" || state.InstallScope != "user" ||
		!filepath.IsAbs(state.InstallRoot) || !filepath.IsAbs(state.CommandDir) || !filepath.IsAbs(state.DataRoot) ||
		!pathidentity.Same(state.InstallRoot, commandDir) || !pathidentity.Same(state.CommandDir, commandDir) {
		return "", installedSkillScannerError(errors.New("installer identity does not bind this gateway"))
	}
	scriptsDir := filepath.Join(state.DataRoot, ".venv", "Scripts")
	installed := filepath.Join(scriptsDir, "skill-scanner.exe")
	if err := skillScannerPathHasNoReparsePoints(installed); err != nil {
		return "", installedSkillScannerError(err)
	}
	for _, path := range []string{state.DataRoot, filepath.Dir(scriptsDir), scriptsDir} {
		if err := safefile.ValidatePrivateDirectoryOwnershipAllowingAdministrators(path); err != nil {
			return "", installedSkillScannerError(err)
		}
	}
	if err := safefile.ValidatePrivateFileOwnershipAllowingAdministrators(installed); err != nil {
		return "", installedSkillScannerError(err)
	}
	// The CLI wheel installs defenseclaw-skill-scanner.exe beside it: the same
	// scanner run through the fix that accepts a well-formed judge answer from
	// any supported model (GAP-2609). An older wheel has no such entry point
	// and keeps skill-scanner.exe; a present but redirected or foreign-owned
	// entry point is refused like the scanner itself.
	compat := filepath.Join(scriptsDir, judgeCompatSkillScanner+".exe")
	if _, err := os.Lstat(compat); errors.Is(err, os.ErrNotExist) {
		return installed, nil
	} else if err != nil {
		return "", installedSkillScannerError(err)
	}
	if err := skillScannerPathHasNoReparsePoints(compat); err != nil {
		return "", installedSkillScannerError(err)
	}
	if err := safefile.ValidatePrivateFileOwnershipAllowingAdministrators(compat); err != nil {
		return "", installedSkillScannerError(err)
	}
	return compat, nil
}

func installedSkillScannerError(err error) error {
	return fmt.Errorf("scanner: installed skill-scanner is unavailable: %w; repair the DefenseClaw installation (PATH fallback refused)", err)
}

func skillScannerPathHasNoReparsePoints(path string) error {
	for current := filepath.Clean(path); ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || fileInfoIsReparsePoint(info) {
			return fmt.Errorf("installed scanner path is redirected: %s", current)
		}
		if filepath.Dir(current) == current {
			return nil
		}
	}
}
