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
// command line, arguments or environment. Image, the Windows executable path,
// is read only to attribute a service-context scan's process to the profile
// it runs from (attributeProcessOwners) and never leaves the detector.
type processInfo struct {
	PID       int
	PPID      int
	User      string
	Comm      string
	StartedAt time.Time
	Connector string
	Windows   bool
	Image     string
	// OwnerID (a SID) and OwnerName name the account whose profile holds
	// Image.
	OwnerID   string
	OwnerName string
	// SessionOwnerID (Windows) is the SID of the account the process runs
	// as, from Remote Desktop Services: its token SID where visible, else
	// the account signed in to its session. Empty in session 0.
	SessionOwnerID string
	// Argv0 is the basename of argv[0] on Linux, kept only when it differs
	// from Comm. A runtime that renames its main thread hides the command
	// from comm: cursor-agent runs `exec -a "$0" node ...` and Node names
	// the thread MainThread (GAP-1207). Never any other argument.
	Argv0 string
	// Argv0Target is the basename argv[0] resolves to when it is an absolute
	// symlink, kept only when it differs (Cursor's `agent` alias, GAP-1865).
	Argv0Target string
}

type windowsProcessEntry struct {
	PID  int
	PPID int
	Comm string
	// SessionOwnerID: see processInfo.SessionOwnerID.
	SessionOwnerID string
}

type windowsProcessDetails struct {
	User      string
	StartedAt time.Time
	// Image is the executable's path, which Windows reports without opening
	// the process, so it is known even where the token owner is not.
	Image string
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
			User: details.User, StartedAt: details.StartedAt, Image: details.Image, Windows: true,
			SessionOwnerID: entry.SessionOwnerID,
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
// distinguish Claude Code from Claude Desktop, so that one basename is settled
// by its executable path (windowsClaudeCodeImage). A node child may inherit only a
// Codex or Claude Code parent, which covers managed npm launchers without
// turning desktop-app helper processes into additional product instances.
func classifyWindowsProcesses(procs []processInfo, catalog []AISignature) {
	aliases := windowsProcessAliases(catalog)
	claudeCode, cursor := false, false
	for _, sig := range catalog {
		claudeCode = claudeCode || normalizeAIID(sig.ID) == "claudecode"
		cursor = cursor || normalizeAIID(sig.ID) == "cursor"
	}
	byPID := make(map[int]*processInfo, len(procs))
	for i := range procs {
		byPID[procs[i].PID] = &procs[i]
		name := normalizedWindowsProcessName(procs[i].Comm)
		if connector := aliases[name]; connector != "" {
			procs[i].Connector = connector
		} else if name == "claude" && claudeCode && windowsClaudeCodeImage(procs[i].Image) {
			procs[i].Connector = "claudecode"
		} else if name == "node" && cursor && windowsCursorAgentImage(procs[i].Image) {
			procs[i].Connector = "cursor"
		}
	}
	// A helper an agent starts from its own executable is part of that run:
	// cursor-agent's worker-server is a second cursor-agent node.exe
	// (GAP-1849) and Amp's plugin runtimes are amp.exe children of amp.exe
	// (GAP-1965). Fold each into its parent so one run is one process.
	// The Copilot CLI runs its engine as a copilot-runtime.exe child; that
	// engine alone is VS Code Copilot Chat's agent host (GAP-2043).
	var helpers []int
	for i := range procs {
		if procs[i].Connector == "" {
			continue
		}
		name := normalizedWindowsProcessName(procs[i].Comm)
		if parent := byPID[procs[i].PPID]; parent != nil && parent.PID != procs[i].PID && parent.Connector == procs[i].Connector &&
			(normalizedWindowsProcessName(parent.Comm) == name || name == "copilot-runtime") {
			helpers = append(helpers, i)
		}
	}
	// Siblings from the same executable (same image and account) whose
	// parent has exited are one run as well: Codex's app-server daemon and
	// its pid-update-loop helper are two codex.exe processes whose launcher
	// is gone (GAP-2021). The earliest started one stays. Without a known
	// image nothing proves they are the same executable.
	type orphanRun struct {
		ppid                         int
		connector, name, image, user string
	}
	firstOrphan := map[orphanRun]int{}
	for i := range procs {
		if procs[i].Connector == "" || procs[i].PPID <= 0 || byPID[procs[i].PPID] != nil || strings.TrimSpace(procs[i].Image) == "" {
			continue
		}
		run := orphanRun{procs[i].PPID, procs[i].Connector, normalizedWindowsProcessName(procs[i].Comm),
			strings.ToLower(procs[i].Image), strings.ToLower(procs[i].User)}
		first, seen := firstOrphan[run]
		switch {
		case !seen:
			firstOrphan[run] = i
		case windowsProcessStartedBefore(procs[i], procs[first]):
			firstOrphan[run] = i
			helpers = append(helpers, first)
		default:
			helpers = append(helpers, i)
		}
	}
	for _, i := range helpers {
		procs[i].Connector = ""
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

// windowsProcessStartedBefore orders two processes by start time, then by
// PID when a start time is unknown or equal, so every scan keeps the same one.
func windowsProcessStartedBefore(a, b processInfo) bool {
	if !a.StartedAt.IsZero() && !b.StartedAt.IsZero() && !a.StartedAt.Equal(b.StartedAt) {
		return a.StartedAt.Before(b.StartedAt)
	}
	return a.PID < b.PID
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

// windowsClaudeCodeImage resolves the claude.exe basename that Claude Code
// and Claude Desktop share by the executable path: Claude Code's native
// installer and its npm package keep claude.exe under these folders, which
// Claude Desktop never uses. Any other path stays ambiguous and unclassified.
func windowsClaudeCodeImage(image string) bool {
	image = strings.ToLower(strings.ReplaceAll(image, "/", `\`))
	for _, marker := range []string{`\.local\bin\`, `\.local\share\claude\`, `\node_modules\@anthropic-ai\claude-code\`} {
		if strings.Contains(image, marker) {
			return true
		}
	}
	return false
}

// windowsCursorAgentImage reports the node.exe that cursor-agent ships and
// runs as on Windows (%LOCALAPPDATA%\cursor-agent\versions\<version>\node.exe),
// so its runs are discovered like other agents' (GAP-1738).
func windowsCursorAgentImage(image string) bool {
	image = strings.ToLower(strings.ReplaceAll(image, "/", `\`))
	return strings.Contains(image, `\appdata\local\cursor-agent\versions\`) && strings.HasSuffix(image, `\node.exe`)
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
