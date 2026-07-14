// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Package nativeinstallstate reads the installer-owned identity adjacent to a
// native Windows executable. It lets launchers restore the exact data and
// connector homes selected at install time without trusting a project or
// stale terminal environment.
package nativeinstallstate

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const maxStateBytes = 128 << 10

type State struct {
	SchemaVersion   int    `json:"schema_version"`
	InstallKind     string `json:"install_kind"`
	InstallScope    string `json:"install_scope"`
	InstallRoot     string `json:"install_root"`
	CommandDir      string `json:"command_dir"`
	DataRoot        string `json:"data_root"`
	Runtime         string `json:"runtime"`
	CodexHome       string `json:"codex_home,omitempty"`
	ClaudeConfigDir string `json:"claude_config_dir,omitempty"`
}

// Environment removes ambient profile selectors and restores the exact
// installer-owned values. Empty connector homes are retained only for legacy
// state written before those fields existed; current setup always records both.
func (state State) Environment(base []string) []string {
	owned := map[string]bool{
		"DEFENSECLAW_INSTALL_ROOT": true,
		"DEFENSECLAW_HOME":         true,
	}
	if state.CodexHome != "" {
		owned["CODEX_HOME"] = true
	}
	if state.ClaudeConfigDir != "" {
		owned["CLAUDE_CONFIG_DIR"] = true
	}
	result := make([]string, 0, len(base)+4)
	for _, entry := range base {
		name, _, ok := strings.Cut(entry, "=")
		if !ok || owned[strings.ToUpper(name)] {
			continue
		}
		result = append(result, entry)
	}
	result = append(result,
		"DEFENSECLAW_INSTALL_ROOT="+state.InstallRoot,
		"DEFENSECLAW_HOME="+state.DataRoot,
	)
	if state.CodexHome != "" {
		result = append(result, "CODEX_HOME="+state.CodexHome)
	}
	if state.ClaudeConfigDir != "" {
		result = append(result, "CLAUDE_CONFIG_DIR="+state.ClaudeConfigDir)
	}
	return result
}

func loadAt(executable, installRoot string) (State, error) {
	var state State
	executable, err := filepath.Abs(executable)
	if err != nil {
		return state, fmt.Errorf("resolve executable path: %w", err)
	}
	installRoot, err = filepath.Abs(installRoot)
	if err != nil {
		return state, fmt.Errorf("resolve install root: %w", err)
	}
	commandDir := filepath.Join(installRoot, "bin")
	if !samePath(filepath.Dir(executable), commandDir) {
		return state, errors.New("native executable is not an immediate child of the installed command directory")
	}
	statePath := filepath.Join(installRoot, "installer", "install-state.json")
	for _, path := range []string{installRoot, commandDir, executable, statePath} {
		if !safePath(path) {
			return state, fmt.Errorf("native install path is missing, redirected, or unsafe: %s", path)
		}
	}
	file, err := os.Open(statePath)
	if err != nil {
		return state, fmt.Errorf("open native install state: %w", err)
	}
	before, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return state, fmt.Errorf("inspect native install state: %w", err)
	}
	if !before.Mode().IsRegular() || before.Size() > maxStateBytes {
		_ = file.Close()
		return state, errors.New("native install state is not a bounded regular file")
	}
	body, readErr := io.ReadAll(io.LimitReader(file, maxStateBytes+1))
	after, statErr := file.Stat()
	closeErr := file.Close()
	if readErr != nil {
		return state, fmt.Errorf("read native install state: %w", readErr)
	}
	if statErr != nil {
		return state, fmt.Errorf("reinspect native install state: %w", statErr)
	}
	if closeErr != nil {
		return state, fmt.Errorf("close native install state: %w", closeErr)
	}
	if len(body) > maxStateBytes || !os.SameFile(before, after) || before.Size() != after.Size() || before.ModTime() != after.ModTime() {
		return state, errors.New("native install state changed while it was being read")
	}
	if err := json.Unmarshal(body, &state); err != nil {
		return State{}, fmt.Errorf("parse native install state: %w", err)
	}
	if state.SchemaVersion != 1 || state.InstallKind != "native-windows-exe" || state.InstallScope != "user" {
		return State{}, errors.New("native install state has an unsupported identity")
	}
	expected := [][2]string{
		{state.InstallRoot, installRoot},
		{state.CommandDir, commandDir},
		{state.Runtime, filepath.Join(installRoot, "runtime", "python")},
	}
	for _, pair := range expected {
		if !absoluteCleanPath(pair[0]) || !samePath(pair[0], pair[1]) {
			return State{}, errors.New("native install state does not match its physical installation")
		}
	}
	for _, value := range []string{state.DataRoot, state.CodexHome, state.ClaudeConfigDir} {
		if value != "" && !absoluteCleanPath(value) {
			return State{}, errors.New("native install state contains an invalid profile path")
		}
	}
	if state.DataRoot == "" {
		return State{}, errors.New("native install state has no data root")
	}
	return state, nil
}

func absoluteCleanPath(path string) bool {
	return path != "" && !strings.ContainsAny(path, "\x00\r\n") && filepath.IsAbs(path) && filepath.Clean(path) == path
}
