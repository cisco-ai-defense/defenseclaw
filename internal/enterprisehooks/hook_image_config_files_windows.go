//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/hermespath"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// WindowsHookConfigFile is one path WindowsManagedHookConfigFiles lists.
// User is true for a path inside the enrolled account's home (the account
// can write it), and Home is then that home: the caller reads the path only
// when no link lies from Home down to it. A machine path a connector also
// watches (Claude Code's managed-settings.d) is not an account's. A path can
// be a folder: the caller expands it to its regular files.
type WindowsHookConfigFile struct {
	Path string
	User bool
	Home string
	// SID is the enrolled account of an account file (User).
	SID string
	// Unverified, when set, says why the account's file at Path cannot be
	// vouched for and is not read: its agent home could not be resolved
	// (a signed-out Hermes account) or lies outside the account home. The
	// caller treats it as an account file it could not read (retire stays
	// pending, rel-1-0-10 GAP-0884, turev #4).
	Unverified string
}

// WindowsManagedHookConfigFiles lists, for every enabled target of the
// guardian's manifest, the agent config paths its connector's hooks live in
// (connector.HookPolicyWatchPathsForConnector, the set the guardian watches)
// and the files its managed install writes beside them that name the hook
// (connector.ManagedAccountHookCompanionPaths), resolved for that account's
// home. GAP-0751 prune and retire read them for references to a launch
// folder. The manifest is the standalone guardian's, so every standalone
// connector is known here whatever profile the calling shell carries: retire
// and prune run in an administrator's or SYSTEM shell without the service
// pins, and a registry built from that process's profile knew only Codex,
// Claude Code, Cursor and Copilot, so retire never read a Hermes, Kiro,
// OpenCode, Antigravity, Devin or Amp account's configs and ended ok over
// them (rel-1-0-10 GAP-0880). A target whose home no longer exists is skipped
// (its configs went with it); a connector this release does not know, and
// any other problem, is returned, which makes the caller's scan incomplete.
func WindowsManagedHookConfigFiles(manifestPath string) ([]WindowsHookConfigFile, []string) {
	manifest, err := LoadManifest(manifestPath)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, []string{fmt.Sprintf("%s: %v", manifestPath, err)}
	}
	registry := newWindowsStandaloneHookConfigRegistry()
	// The guardian resolves each account's files with its service
	// environment, which sets no agent home; an administrator's shell may
	// (rel-1-0-10 GAP-0885: CODEX_HOME or OPENCODE_CONFIG_DIR made retire
	// read the administrator's folder, as a machine file, for every account).
	restore := withoutCallerAgentHomes()
	defer restore()
	var files []WindowsHookConfigFile
	var problems []string
	for _, target := range manifest.Targets {
		if target.Enabled != nil && !*target.Enabled {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(target.Connector))
		home := strings.TrimSpace(target.UserHome)
		if name == "" || home == "" {
			continue
		}
		if _, err := os.Lstat(home); errors.Is(err, fs.ErrNotExist) {
			continue
		}
		conn, ok := registry.Get(name)
		if !ok {
			problems = append(problems, fmt.Sprintf("%s (%s): not a connector this release knows, so its agent configs were not read", home, name))
			continue
		}
		dataDir, err := resolveWindowsEnterpriseDataDir(home, target.DataDir)
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s (%s): %v", home, name, err))
			continue
		}
		sid := strings.TrimSpace(target.SID)
		if name == "hermes" {
			// The Hermes home is the account's HERMES_HOME, read from its
			// loaded registry hive. A signed-out account's hive is not
			// loaded: the profile default is then no proof of where its
			// Hermes reads, so the account is unverified, never read at the
			// default (rel-1-0-10 GAP-0884).
			if _, err := hermespath.ConfigPathForAccount(home); err != nil {
				reason := "Hermes home not resolvable: " + err.Error()
				if errors.Is(err, hermespath.ErrAccountSignedOut) {
					reason = "signed out, Hermes home not resolvable while its registry hive is not loaded (HERMES_HOME may move it): " + err.Error()
				}
				files = append(files, WindowsHookConfigFile{Path: hermespath.ConfigPathForUserHome(home), User: true, Home: home, SID: sid, Unverified: reason})
				continue
			}
		}
		setup := connector.SetupOpts{DataDir: dataDir, ManagedEnterprise: true}
		var paths []string
		if err := connector.WithUserHomeDir(home, func() error {
			paths = append(connector.HookPolicyWatchPathsForConnector(conn, setup),
				connector.ManagedAccountHookCompanionPaths(conn, setup)...)
			return nil
		}); err != nil {
			problems = append(problems, fmt.Sprintf("%s (%s): %v", home, name, err))
			continue
		}
		for _, path := range paths {
			file := WindowsHookConfigFile{Path: path}
			switch {
			case windowsPathWithin(home, path):
				file.User, file.Home, file.SID = true, home, sid
			case windowsPathInProgramFiles(path):
				// A machine path the connector also watches (Claude Code's
				// managed settings): only an administrator writes there.
			default:
				// An agent home the account moved out of its profile is
				// still the account's: never a machine file (turev #4).
				file.User, file.Home, file.SID = true, home, sid
				file.Unverified = "outside the account home " + home + " (a moved agent home); not read as SYSTEM"
			}
			files = append(files, file)
		}
	}
	return files, problems
}

// newWindowsStandaloneHookConfigRegistry is every connector the standalone
// guardian installs, independent of this process's profile.
func newWindowsStandaloneHookConfigRegistry() *connector.Registry {
	registry := connector.NewRegistry()
	registry.RegisterBuiltin(connector.NewCodexConnector())
	registry.RegisterBuiltin(connector.NewClaudeCodeConnector())
	registry.RegisterBuiltin(connector.NewCursorConnector())
	registerWindowsStandalonePerUserConnectors(registry)
	return registry
}

// windowsCallerAgentHomes are the environment variables that move an agent's
// home; the guardian's service environment sets none of them.
var windowsCallerAgentHomes = []string{
	"CODEX_HOME", "CLAUDE_CONFIG_DIR", "CLAUDE_CODE_PLUGIN_CACHE_DIR", "OPENCODE_CONFIG_DIR", "OPENCODE_CONFIG",
	"COPILOT_HOME", "XDG_CONFIG_HOME", "HERMES_HOME",
}

// withoutCallerAgentHomes unsets windowsCallerAgentHomes until restore runs.
func withoutCallerAgentHomes() (restore func()) {
	previous := map[string]string{}
	for _, name := range windowsCallerAgentHomes {
		if value, set := os.LookupEnv(name); set {
			previous[name] = value
			_ = os.Unsetenv(name)
		}
	}
	return func() {
		for name, value := range previous {
			_ = os.Setenv(name, value)
		}
	}
}

// windowsPathInProgramFiles reports whether path lies below the trusted
// Program Files folder.
func windowsPathInProgramFiles(path string) bool {
	programFiles, err := winpath.TrustedProgramFiles()
	return err == nil && windowsPathWithin(programFiles, path)
}
