// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"path"
	"strings"
	"time"
)

// processInfo is deliberately data-minimized. In particular, it never holds a
// command line, arguments, environment, or full executable path.
type processInfo struct {
	PID       int
	PPID      int
	User      string
	Comm      string
	StartedAt time.Time
	Connector string
	Windows   bool
}

type windowsProcessEntry struct {
	PID  int
	PPID int
	Comm string
}

type windowsProcessDetails struct {
	User      string
	StartedAt time.Time
}

type windowsSnapshotReader interface {
	List() ([]windowsProcessEntry, error)
	Details(pid int) (windowsProcessDetails, error)
}

// collectWindowsSnapshot keeps the snapshot-level failure distinct from
// per-process races and authorization failures. Toolhelp supplies enough base
// metadata to retain a matching process even when its handle cannot be opened.
func collectWindowsSnapshot(reader windowsSnapshotReader) ([]processInfo, error) {
	entries, err := reader.List()
	if err != nil {
		return nil, err
	}
	infos := make([]processInfo, 0, len(entries))
	for _, entry := range entries {
		comm := windowsProcessBasename(entry.Comm)
		if entry.PID <= 0 || comm == "" {
			continue
		}
		details, _ := reader.Details(entry.PID)
		infos = append(infos, processInfo{
			PID: entry.PID, PPID: entry.PPID, Comm: comm,
			User: details.User, StartedAt: details.StartedAt, Windows: true,
		})
	}
	return infos, nil
}

func processSnapshot() ([]processInfo, error) {
	return processSnapshotSource()
}

var processSnapshotSource = platformProcessSnapshot

// classifyWindowsProcesses uses executable basenames only. Exact aliases are
// intentionally narrow; an unrelated command whose arguments mention an AI
// product is never visible to this classifier. Ambiguous catalog aliases fail
// closed: for example, a basename-only Claude.exe observation cannot safely
// distinguish Claude Code from Claude Desktop. A node child may inherit only a
// Codex or Claude Code parent, which covers managed npm launchers without
// turning desktop-app helper processes into additional product instances.
func classifyWindowsProcesses(procs []processInfo, catalog []AISignature) {
	aliases := windowsProcessAliases(catalog)
	byPID := make(map[int]*processInfo, len(procs))
	for i := range procs {
		byPID[procs[i].PID] = &procs[i]
		if connector := aliases[normalizedWindowsProcessName(procs[i].Comm)]; connector != "" {
			procs[i].Connector = connector
		}
	}
	for i := 0; i < len(procs); i++ {
		if procs[i].Connector != "" || normalizedWindowsProcessName(procs[i].Comm) != "node" {
			continue
		}
		seen := map[int]bool{procs[i].PID: true}
		for parent := byPID[procs[i].PPID]; parent != nil && !seen[parent.PID]; parent = byPID[parent.PPID] {
			seen[parent.PID] = true
			if parent.Connector != "" {
				if windowsNodeParentConnector(parent.Connector) {
					procs[i].Connector = parent.Connector
				}
				break
			}
		}
	}
}

// windowsProcessAliases builds one exact basename index for every catalog
// signature. Multiple case/suffix spellings owned by the same signature are
// harmless, while aliases claimed by different signatures are omitted so a
// basename alone cannot invent a product identity.
func windowsProcessAliases(catalog []AISignature) map[string]string {
	owners := make(map[string]map[string]struct{})
	present := make(map[string]bool, len(catalog))
	add := func(alias, id string) {
		alias = normalizedWindowsProcessName(alias)
		id = normalizeAIID(id)
		if alias == "" || id == "" {
			return
		}
		if owners[alias] == nil {
			owners[alias] = make(map[string]struct{})
		}
		owners[alias][id] = struct{}{}
	}
	for _, sig := range catalog {
		id := normalizeAIID(sig.ID)
		if id == "" {
			continue
		}
		present[id] = true
		for _, name := range sig.ProcessNames {
			add(name, id)
		}
	}

	// These native/npm launcher basenames are intentionally recognized even
	// when an older/custom catalog lists only the primary command name.
	for id, aliases := range map[string][]string{
		"codex":      {"codex", "codex-app-server", "codex-exec", "codex_exec"},
		"claudecode": {"claude", "claude-code"},
	} {
		if !present[id] {
			continue
		}
		for _, alias := range aliases {
			add(alias, id)
		}
	}

	resolved := make(map[string]string, len(owners))
	for alias, ids := range owners {
		if len(ids) != 1 {
			continue
		}
		for id := range ids {
			resolved[alias] = id
		}
	}
	return resolved
}

func windowsNodeParentConnector(connector string) bool {
	switch normalizeAIID(connector) {
	case "codex", "claudecode":
		return true
	default:
		return false
	}
}

func normalizedWindowsProcessName(value string) string {
	name := windowsProcessBasename(value)
	for _, suffix := range []string{".exe", ".cmd"} {
		name = strings.TrimSuffix(name, suffix)
	}
	return name
}

func windowsProcessBasename(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	return strings.ToLower(path.Base(strings.ReplaceAll(value, `\`, "/")))
}
