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
// intentionally narrow; an unrelated command whose arguments mention an agent
// is never visible to this classifier. A node child may inherit an already
// classified parent, which covers managed npm launchers without reading argv.
func classifyWindowsProcesses(procs []processInfo, catalog []AISignature) {
	aliases := map[string]string{
		"codex":            "codex",
		"codex-app-server": "codex",
		"codex-exec":       "codex",
		"codex_exec":       "codex",
		"claude":           "claudecode",
		"claude-code":      "claudecode",
	}
	allowed := make(map[string]bool, len(catalog))
	for _, sig := range catalog {
		if sig.ID == "codex" || sig.ID == "claudecode" {
			allowed[sig.ID] = true
			for _, name := range sig.ProcessNames {
				if normalizedWindowsProcessName(name) != "" {
					aliases[normalizedWindowsProcessName(name)] = sig.ID
				}
			}
		}
	}
	byPID := make(map[int]*processInfo, len(procs))
	for i := range procs {
		byPID[procs[i].PID] = &procs[i]
		if connector := aliases[normalizedWindowsProcessName(procs[i].Comm)]; allowed[connector] {
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
				procs[i].Connector = parent.Connector
				break
			}
		}
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
