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
	"io"
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

// windowsMachineScopedCursorPackageJSON points at Cursor's per-machine
// install (MSI installer, admin-installed). Unlike the per-user candidates
// this path is NOT derived from the profile home — every user on the box
// sees the same version. Kept as a package-level variable so tests can
// stub it to a hermetic `t.TempDir()` fixture instead of trying to write
// to the real Program Files tree.
var windowsMachineScopedCursorPackageJSON = `C:\Program Files\Cursor\resources\app\package.json`

// windowsAgentVersionCandidatePaths returns the ordered set of
// package.json paths to try for `connectorName` under
// `profileHome`. The order matters: probes higher in the list are
// preferred (first match wins). Each connector's candidate set covers the
// install flavours we've observed on real Windows QA hosts plus the
// major package managers users install these CLIs through in practice —
// a probe list too narrow becomes a silent-drop when the user installed
// via a channel we didn't cover (real customer symptom on macOS drove
// the presence-fallback in packaging/macos/lib/installer_lib.sh; the
// probe broadening here is the Windows-side coverage improvement).
//
// Per-connector candidates:
//
//   - `claudecode`:
//     1. `%APPDATA%\npm\node_modules\@anthropic-ai\claude-code\package.json`
//     — npm-global (the historical baseline).
//     2. `%USERPROFILE%\.bun\install\global\node_modules\@anthropic-ai\claude-code\package.json`
//     — Bun global install (`bun install -g @anthropic-ai/claude-code`).
//     3. `%LOCALAPPDATA%\Yarn\Data\global\node_modules\@anthropic-ai\claude-code\package.json`
//     — Yarn Classic global install (still common on legacy hosts).
//
//   - `codex`:
//     1. `%APPDATA%\npm\node_modules\@openai\codex\package.json` — npm-global.
//     2. `%USERPROFILE%\.bun\install\global\node_modules\@openai\codex\package.json`
//     — Bun global.
//     3. `%LOCALAPPDATA%\Yarn\Data\global\node_modules\@openai\codex\package.json`
//     — Yarn Classic global.
//     MSIX-store install (`C:\Program Files\WindowsApps\OpenAI.Codex_…\`) still
//     requires a glob-resolved lookup and stays out of scope here; a follow-up
//     probe can add it once the glob-vs-reparse-chain interaction is worked out.
//
//   - `cursor`:
//     1. `%LOCALAPPDATA%\Programs\cursor\resources\app\package.json`
//     — Cursor Desktop per-user install.
//     2. `windowsMachineScopedCursorPackageJSON` — Cursor MSI machine-scoped
//     install. Path is a package variable so tests can override; the
//     production default is `C:\Program Files\Cursor\resources\app\package.json`.
//
// All per-user candidates are fully-cleaned absolute paths anchored inside
// `profileHome`; the one machine-scoped candidate is anchored at a fixed
// system root and reads the same package.json for every user (correct: it
// documents the version of the shared install on the box).
func windowsAgentVersionCandidatePaths(profileHome, connectorName string) []string {
	appDataRoaming := filepath.Join(profileHome, "AppData", "Roaming")
	appDataLocal := filepath.Join(profileHome, "AppData", "Local")
	bunGlobal := filepath.Join(profileHome, ".bun", "install", "global", "node_modules")
	yarnGlobal := filepath.Join(appDataLocal, "Yarn", "Data", "global", "node_modules")
	switch connectorName {
	case "claudecode":
		return []string{
			filepath.Join(appDataRoaming, "npm", "node_modules", "@anthropic-ai", "claude-code", "package.json"),
			filepath.Join(bunGlobal, "@anthropic-ai", "claude-code", "package.json"),
			filepath.Join(yarnGlobal, "@anthropic-ai", "claude-code", "package.json"),
		}
	case "codex":
		return []string{
			filepath.Join(appDataRoaming, "npm", "node_modules", "@openai", "codex", "package.json"),
			filepath.Join(bunGlobal, "@openai", "codex", "package.json"),
			filepath.Join(yarnGlobal, "@openai", "codex", "package.json"),
		}
	case "cursor":
		return []string{
			filepath.Join(appDataLocal, "Programs", "cursor", "resources", "app", "package.json"),
			windowsMachineScopedCursorPackageJSON,
		}
	default:
		return nil
	}
}

// readBoundedWindowsAgentPackageJSON opens `candidate`, applies the
// trust checks (reparse-chain rejection, regular-file check), and
// returns at most `windowsAgentVersionMaxBytes` bytes. Any of these
// conditions returns a non-nil error and empty payload:
//
//   - `candidate` is empty or its ancestor chain crosses a Windows
//     junction / symlink (per `winpath.RejectReparseChain`);
//   - the target is a symlink / non-regular file;
//   - `os.Open` fails;
//   - `io.ReadAll` on an `io.LimitReader(f, max+1)` returns more
//     than `windowsAgentVersionMaxBytes` bytes — i.e. the on-disk
//     file grew past the ceiling between check and read.
//
// The +1-byte trick lets the caller distinguish "read exactly `max`
// bytes and the file is at least that big" from "file is strictly
// larger than `max`, we should reject" without ever allocating a
// slice larger than `max + 1`. This closes the Lstat -> ReadFile
// race a hostile profile owner could exploit to force the
// LocalSystem enumerator to allocate an arbitrarily large buffer:
// even if the file grew between checks, our read is capped.
//
// The old shape — `os.Lstat` (size check) then `os.ReadFile` (no
// cap) — was flagged by CodeRabbit as a resource-exhaustion
// vector. This helper is the fix.
func readBoundedWindowsAgentPackageJSON(candidate string) ([]byte, error) {
	if strings.TrimSpace(candidate) == "" {
		return nil, errors.New("empty candidate path")
	}
	// Ancestor reparse-point rejection: refuses to open any path
	// whose parent chain crosses a Windows junction or symbolic
	// link. Mirrors the treatment applied to the enumerator's
	// ProfileImagePath reads (see enumerator_windows.go).
	if err := winpath.RejectReparseChain(candidate); err != nil {
		return nil, err
	}
	// Lstat is retained as a fast-path for the leaf shape check
	// (symlink / non-regular files bypass reading entirely). The
	// authoritative size check runs on the opened handle below.
	if info, err := os.Lstat(candidate); err != nil {
		return nil, err
	} else if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("candidate is not a regular file: mode=%s", info.Mode())
	}
	f, err := os.Open(candidate)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, windowsAgentVersionMaxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > windowsAgentVersionMaxBytes {
		return nil, fmt.Errorf("candidate exceeds bounded size %d", windowsAgentVersionMaxBytes)
	}
	return data, nil
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
	data, err := readBoundedWindowsAgentPackageJSON(candidate)
	if err != nil {
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
		data, err := readBoundedWindowsAgentPackageJSON(candidate)
		if err != nil {
			// Preserve the historical operator-facing reason
			// strings where the caller distinguishes shapes; the
			// bounded helper collapses reparse / regular-file /
			// size errors into typed messages we can categorize
			// here without leaking full paths.
			if errors.Is(err, os.ErrNotExist) {
				lastReason = fmt.Sprintf("no %s package.json under this profile", connectorName)
				continue
			}
			msg := err.Error()
			switch {
			case strings.Contains(msg, "reparse"):
				lastReason = "ancestor reparse chain refused"
			case strings.Contains(msg, "regular file"):
				lastReason = "candidate is not a regular file"
			case strings.Contains(msg, "exceeds bounded size"):
				lastReason = "candidate exceeds bounded size"
			default:
				// Path-free reason on purpose: os.PathError.Error()
				// embeds the candidate absolute path, which the
				// enumerator forwards to `logfSafely` unredacted.
				// Formatting `err` with `%v` would leak that path
				// to every operator tailing gateway.err.log
				// (including any operator without filesystem
				// visibility into that user profile). The
				// categorized reasons above cover the common
				// diagnostic shapes; anything else is just
				// "candidate read failed."
				lastReason = "candidate read failed"
			}
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
