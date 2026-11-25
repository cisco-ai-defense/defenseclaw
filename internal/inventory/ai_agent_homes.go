// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// Agent folders a user moves with an environment variable. A managed scan
// (Secure Client, standalone enterprise) runs outside the user's sessions, so it reads where
// the user saved the variable: the export lines of the shell startup files,
// or on Windows the user's persistent environment. A variable set only in
// one terminal is not seen.

// agentHomeDefaults maps each variable to the folder the agent uses unset.
var agentHomeDefaults = map[string]string{
	"CODEX_HOME":        ".codex",
	"CLAUDE_CONFIG_DIR": ".claude",
	"COPILOT_HOME":      ".copilot",
}

var agentHomeShellFiles = []string{".zshenv", ".zprofile", ".zshrc", ".bash_profile", ".bashrc", ".profile"}

const maxShellFileBytes = 256 << 10

// savedUserVariable returns the value the user of home (sid on Windows)
// saved for name (replaceable in tests).
var savedUserVariable = platformSavedVariable

// agentHome is the agent folder of home for variable name: the one the user
// saved on a managed scan, else the default.
func (s *ContinuousDiscoveryService) agentHome(home, name string) string {
	if dir := s.savedAgentHome(home, name); dir != "" {
		return dir
	}
	return filepath.Join(home, agentHomeDefaults[name])
}

// savedAgentHome returns the folder the user of home saved for name, or ""
// outside a managed scan, or when the value is not a literal path to a real
// folder inside home.
func (s *ContinuousDiscoveryService) savedAgentHome(home, name string) string {
	if !s.opts.ManagedEnterprise {
		return ""
	}
	owner, _ := s.homeOwnerForPath(home)
	value := strings.TrimSpace(savedUserVariable(home, owner.UserID, name))
	for _, prefix := range []string{"~/", "$HOME/", "${HOME}/", `%USERPROFILE%\`} {
		if len(value) > len(prefix) && strings.EqualFold(value[:len(prefix)], prefix) {
			value = filepath.Join(home, value[len(prefix):])
		}
	}
	dir := filepath.Clean(value)
	rel, err := filepath.Rel(home, dir)
	if !filepath.IsAbs(value) || strings.ContainsAny(value, "$%`") || err != nil || !pathBelow(home, dir) ||
		!realDirsBelow(home, filepath.ToSlash(rel)+"/x") {
		return ""
	}
	return dir
}

// agentHomeCandidate splits a catalog path that starts with an agent folder
// variable ($CODEX_HOME/skills) into the variable and the rest.
func agentHomeCandidate(candidate string) (name, rest string, ok bool) {
	for name := range agentHomeDefaults {
		if rest, ok := strings.CutPrefix(candidate, "$"+name); ok && (rest == "" || rest[0] == '/' || rest[0] == '\\') {
			return name, strings.TrimLeft(rest, `/\`), true
		}
	}
	return "", "", false
}

// shellSavedVariable returns the last literal NAME=value the shell startup
// files of home assign, in the order a login shell reads them.
func shellSavedVariable(home, name string) string {
	value := ""
	for _, file := range agentHomeShellFiles {
		data, err := safefile.ReadRegularFileBounded(filepath.Join(home, file), maxShellFileBytes)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			line = strings.TrimSpace(strings.TrimPrefix(line, "export "))
			if rest, ok := strings.CutPrefix(line, name+"="); ok {
				value = shellWord(rest)
			}
		}
	}
	return value
}

// shellWord is the first word of rest: a quoted string, or text up to a
// space, ';' or '#'.
func shellWord(rest string) string {
	if rest != "" && (rest[0] == '"' || rest[0] == '\'') {
		if end := strings.IndexByte(rest[1:], rest[0]); end >= 0 {
			return rest[1 : 1+end]
		}
		return ""
	}
	if end := strings.IndexAny(rest, " \t;#"); end >= 0 {
		return rest[:end]
	}
	return rest
}
