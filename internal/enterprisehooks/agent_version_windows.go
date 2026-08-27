// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// windowsAgentVersionMaxBytes caps how many bytes any single
// version-probe read is allowed to consume. package.json files for
// modern npm-installed CLIs sit around 1–4 KiB; the ceiling exists
// so a hostile user profile cannot induce the enumerator (running as
// LocalSystem) to slurp an arbitrarily large blob just by dropping a
// giant file at the probed path. Kept well above realistic sizes so
// a legitimate agent update never trips it.
const windowsAgentVersionMaxBytes = 64 * 1024

// windowsAgentPackageJSON is the shape we care about — just the
// `version` field. json.Decoder.DisallowUnknownFields is NOT used
// because npm CLIs ship dozens of other fields; we ignore them.
type windowsAgentPackageJSON struct {
	Version string `json:"version"`
}

// discoverWindowsAgentVersion returns a per-user agent version for
// `connectorName` under the target's home directory `profileHome`,
// or an empty string if:
//   - the connector is not one this probe knows about,
//   - the CLI is not installed under any known path in this
//     profile,
//   - the version metadata file exists but is unreadable, exceeds
//     the bounded size, or fails JSON parse,
//   - any ancestor of the probed path is a reparse point (Windows
//     junction / mount point) — refused for the same reason
//     `winpath.RejectReparseChain` is used elsewhere in the
//     enumerator: a per-user reparse chain could redirect a read
//     into a system directory and let a user profile influence
//     what the LocalSystem enumerator ingests.
//
// The macOS analogue is `discover_agent_version` in
// `packaging/macos/lib/installer_lib.sh`, which returns empty for
// the same reasons. The enumerator caller drops any user × connector
// with empty discovery — mirroring macOS's silently-skip behaviour.
//
// No process is ever spawned; all reads are static filesystem
// inspection of well-known JSON manifests. This keeps the probe
// safe to run as LocalSystem against a hostile user profile — we do
// not execute the discovered binary or ask it to introspect itself.
func discoverWindowsAgentVersion(profileHome, connectorName string) string {
	profileHome = strings.TrimSpace(profileHome)
	connectorName = strings.ToLower(strings.TrimSpace(connectorName))
	if profileHome == "" || connectorName == "" {
		return ""
	}
	if !filepath.IsAbs(profileHome) {
		return ""
	}
	cleanHome := filepath.Clean(profileHome)

	candidates := windowsAgentVersionCandidatePaths(cleanHome, connectorName)
	for _, candidate := range candidates {
		version, ok := readWindowsAgentVersionCandidate(candidate)
		if ok {
			return version
		}
	}
	return ""
}

// windowsAgentVersionCandidatePaths returns the ordered set of
// package.json paths to try for `connectorName` under
// `profileHome`. The order matters: probes higher in the list are
// preferred. Each connector's candidate set covers the install
// flavours we've observed on real Windows QA hosts:
//
//   - `claudecode`: npm-global install under
//     `%APPDATA%\npm\node_modules\@anthropic-ai\claude-code\`.
//     `%APPDATA%` on Windows resolves to
//     `%USERPROFILE%\AppData\Roaming` — the enumerator receives
//     the profile's home directory so we build the Roaming path
//     directly.
//   - `codex`: npm-global install under
//     `%APPDATA%\npm\node_modules\@openai\codex\`. The MSIX-store
//     flavour (`C:\Program Files\WindowsApps\OpenAI.Codex_…\`)
//     lives OUTSIDE the profile and is machine-scoped; probing it
//     is a follow-up that requires a separate lookup path. For
//     now we return empty for MSIX-only installs so the
//     enumerator drops the row (parity with macOS's behaviour when
//     the codex CLI is absent).
//   - `cursor`: Cursor Desktop's per-user install at
//     `%LOCALAPPDATA%\Programs\cursor\resources\app\package.json`.
//     `%LOCALAPPDATA%` = `%USERPROFILE%\AppData\Local`.
//
// Every candidate is a fully-cleaned absolute path anchored inside
// `profileHome`. Callers never see relative paths, symlinks, or
// user-supplied path fragments.
func windowsAgentVersionCandidatePaths(profileHome, connectorName string) []string {
	appDataRoaming := filepath.Join(profileHome, "AppData", "Roaming")
	appDataLocal := filepath.Join(profileHome, "AppData", "Local")
	switch connectorName {
	case "claudecode":
		return []string{
			filepath.Join(appDataRoaming, "npm", "node_modules", "@anthropic-ai", "claude-code", "package.json"),
		}
	case "codex":
		return []string{
			filepath.Join(appDataRoaming, "npm", "node_modules", "@openai", "codex", "package.json"),
		}
	case "cursor":
		return []string{
			filepath.Join(appDataLocal, "Programs", "cursor", "resources", "app", "package.json"),
		}
	default:
		return nil
	}
}

// readWindowsAgentVersionCandidate applies the trust checks and
// bounded read to one candidate path. Returns the version string
// and `true` iff the file exists, its ancestor chain contains no
// reparse points, its size fits under `windowsAgentVersionMaxBytes`,
// and its `version` field parses as a non-empty string.
//
// Every failure returns `"", false` without logging or wrapping —
// the enumerator loops over candidates and treats a false return as
// "try the next one." Silent-drop is the intended shape here; the
// audit trail lives at the enumerator's `[hook-enumerator] audit
// complete` summary line, which reports how many `(SID, Connector)`
// rows were emitted vs skipped.
func readWindowsAgentVersionCandidate(candidate string) (string, bool) {
	if strings.TrimSpace(candidate) == "" {
		return "", false
	}
	// Ancestor reparse-point rejection: refuses to open any path
	// whose parent chain crosses a Windows junction or symbolic
	// link. Mirrors the treatment applied to the enumerator's
	// ProfileImagePath reads (see enumerator_windows.go).
	if err := winpath.RejectReparseChain(candidate); err != nil {
		return "", false
	}
	info, err := os.Lstat(candidate)
	if err != nil {
		return "", false
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return "", false
	}
	if info.Size() > windowsAgentVersionMaxBytes {
		return "", false
	}
	data, err := os.ReadFile(candidate)
	if err != nil {
		return "", false
	}
	// Double-bounded — a race that appended between Lstat and
	// ReadFile still hits the ceiling. Reject rather than parse
	// arbitrary bytes.
	if int64(len(data)) > windowsAgentVersionMaxBytes {
		return "", false
	}
	var parsed windowsAgentPackageJSON
	if err := json.Unmarshal(data, &parsed); err != nil {
		return "", false
	}
	version := strings.TrimSpace(parsed.Version)
	if version == "" {
		return "", false
	}
	return version, true
}

// windowsAgentVersionExplain is a diagnostic wrapper used by the
// enumerator when it wants an operator-facing reason for why a row
// was skipped, without changing the primary silent-drop contract of
// discoverWindowsAgentVersion. Returns a short human-readable
// phrase plus the same "" / version signal. Never leaks path
// contents into the reason string beyond the connector name.
func windowsAgentVersionExplain(profileHome, connectorName string) (string, string) {
	profileHome = strings.TrimSpace(profileHome)
	connectorName = strings.ToLower(strings.TrimSpace(connectorName))
	if profileHome == "" {
		return "", "profile home is empty"
	}
	if !filepath.IsAbs(profileHome) {
		return "", "profile home is not absolute"
	}
	candidates := windowsAgentVersionCandidatePaths(filepath.Clean(profileHome), connectorName)
	if len(candidates) == 0 {
		return "", fmt.Sprintf("no probe defined for connector %q", connectorName)
	}
	var lastReason string
	for _, candidate := range candidates {
		if err := winpath.RejectReparseChain(candidate); err != nil {
			lastReason = "ancestor reparse chain refused"
			continue
		}
		info, err := os.Lstat(candidate)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				lastReason = fmt.Sprintf("no %s package.json under this profile", connectorName)
			} else {
				lastReason = fmt.Sprintf("candidate lstat failed: %v", err)
			}
			continue
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			lastReason = "candidate is not a regular file"
			continue
		}
		if info.Size() > windowsAgentVersionMaxBytes {
			lastReason = "candidate exceeds bounded size"
			continue
		}
		data, err := os.ReadFile(candidate)
		if err != nil {
			lastReason = fmt.Sprintf("candidate read failed: %v", err)
			continue
		}
		if int64(len(data)) > windowsAgentVersionMaxBytes {
			lastReason = "candidate grew past bounded size mid-read"
			continue
		}
		var parsed windowsAgentPackageJSON
		if err := json.Unmarshal(data, &parsed); err != nil {
			lastReason = "candidate is not valid JSON"
			continue
		}
		version := strings.TrimSpace(parsed.Version)
		if version == "" {
			lastReason = "candidate has empty version field"
			continue
		}
		return version, ""
	}
	if lastReason == "" {
		lastReason = "no candidate matched"
	}
	return "", lastReason
}
