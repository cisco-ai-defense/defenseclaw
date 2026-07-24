//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const claudeCodeWindowsPolicyKey = `SOFTWARE\Policies\ClaudeCode`

var claudeCodeWindowsProgramFilesRoot = func() (string, error) {
	return winpath.CurrentUserKnownFolderPath(windows.FOLDERID_ProgramFiles)
}

func claudeCodePlatformManagedSettingsRoot() (string, error) {
	root, err := claudeCodeWindowsProgramFilesRoot()
	if err != nil {
		return "", fmt.Errorf("resolve Windows Program Files Known Folder for Claude Code managed policy: %w", err)
	}
	root = strings.TrimSpace(root)
	if root == "" || !filepath.IsAbs(root) {
		return "", fmt.Errorf("resolve Windows Program Files Known Folder for Claude Code managed policy: invalid path %q", root)
	}
	return filepath.Join(filepath.Clean(root), "ClaudeCode"), nil
}

func loadClaudeCodeOSManagedSettings() (claudeCodeOSManagedSources, error) {
	admin, err := readClaudeCodeWindowsRegistryPolicy(
		registry.LOCAL_MACHINE,
		"MDM/OS managed settings",
		`HKLM\SOFTWARE\Policies\ClaudeCode\Settings`,
	)
	if err != nil {
		return claudeCodeOSManagedSources{}, err
	}
	user, err := readClaudeCodeWindowsRegistryPolicy(
		registry.CURRENT_USER,
		"HKCU managed settings fallback",
		`HKCU\SOFTWARE\Policies\ClaudeCode\Settings`,
	)
	if err != nil {
		return claudeCodeOSManagedSources{}, err
	}
	return claudeCodeOSManagedSources{admin: admin, userFallback: user}, nil
}

func readClaudeCodeWindowsRegistryPolicy(root registry.Key, name, path string) (*claudeCodeSettingsSource, error) {
	key, err := registry.OpenKey(root, claudeCodeWindowsPolicyKey, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if errors.Is(err, registry.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("inspect Claude Code %s %s: %w", name, path, err)
	}
	defer key.Close()
	raw, valueType, err := key.GetStringValue("Settings")
	if errors.Is(err, registry.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read Claude Code %s %s: %w", name, path, err)
	}
	if valueType != registry.SZ && valueType != registry.EXPAND_SZ {
		return nil, fmt.Errorf("Claude Code %s %s has unsupported registry type %d", name, path, valueType)
	}
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	settings, err := decodeClaudeCodeSettings([]byte(raw), fmt.Sprintf("%s (%s)", name, path))
	if err != nil {
		return nil, err
	}
	return &claudeCodeSettingsSource{name: name, path: path, settings: settings}, nil
}
