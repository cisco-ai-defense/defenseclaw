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
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/defenseclaw/defenseclaw/internal/processutil"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

// windowsAgentVersionMaxBytes caps how many bytes any single
// version-probe read is allowed to consume. package.json files for
// modern npm-installed CLIs sit around 1–4 KiB; the ceiling exists
// so a hostile user profile cannot induce the enumerator (running as
// LocalSystem) to slurp an arbitrarily large blob just by dropping a
// giant file at the probed path. Kept well above realistic sizes so
// a legitimate agent update never trips it.
const windowsAgentVersionMaxBytes = 64 * 1024

const windowsNativeAgentProbeTimeout = 10 * time.Second

var (
	windowsNativeCodexRuntimeLeaf    = regexp.MustCompile(`^[0-9A-Fa-f]{8,128}$`)
	windowsNativeAgentVersionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$`)
	windowsNativeAgentVersion        = probeWindowsNativeAgentVersion
)

// windowsNativeAgentProbeScript is executed only by the fixed Windows
// PowerShell binary returned by GetSystemWindowsDirectory. It never executes
// the candidate. The script holds the PE open without write/delete sharing,
// validates Authenticode publisher plus PE identity, and emits one normalized
// version. Candidate values arrive through environment variables rather than
// PowerShell source text, so a profile path cannot become script input.
const windowsNativeAgentProbeScript = `$ErrorActionPreference='Stop'
$connector=$env:DEFENSECLAW_AGENT_CONNECTOR
$path=$env:DEFENSECLAW_AGENT_CANDIDATE
$stream=$null
try {
  $full=[IO.Path]::GetFullPath($path)
  $stream=[IO.FileStream]::new($full,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
  if ($stream.Length -le 0 -or $stream.Length -gt 536870912) { exit 1 }
  $signature=Microsoft.PowerShell.Security\Get-AuthenticodeSignature -LiteralPath $full -ErrorAction Stop
  if ($signature.Status -ne [Management.Automation.SignatureStatus]::Valid -or $null -eq $signature.SignerCertificate) { exit 1 }
  $signer=$signature.SignerCertificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName,$false)
  $identity=[Diagnostics.FileVersionInfo]::GetVersionInfo($full)
  if ($null -eq $identity) { exit 1 }
  if ($connector -ceq 'claudecode') {
    if ($signer -cnotin @('Anthropic PBC','Anthropic, PBC') -or $identity.ProductName -cne 'Claude Code') { exit 1 }
    if (-not [string]::IsNullOrWhiteSpace($identity.OriginalFilename) -and $identity.OriginalFilename -cne 'claude.exe') { exit 1 }
    $match=[regex]::Match([string]$identity.FileVersion,'^([0-9]+)\.([0-9]+)\.([0-9]+)(?:\.0)?$',[Text.RegularExpressions.RegexOptions]::CultureInvariant)
    if (-not $match.Success) { exit 1 }
    [Console]::Out.WriteLine($match.Groups[1].Value+'.'+$match.Groups[2].Value+'.'+$match.Groups[3].Value)
    exit 0
  }
  if ($connector -cne 'codex' -or $signer -cne 'OpenAI OpCo, LLC') { exit 1 }
  if (-not [string]::IsNullOrWhiteSpace($identity.ProductName) -and $identity.ProductName -cnotin @('Codex','Codex CLI')) { exit 1 }
  if (-not [string]::IsNullOrWhiteSpace($identity.OriginalFilename) -and $identity.OriginalFilename -cnotin @('codex.exe','codex-x86_64-pc-windows-msvc.exe')) { exit 1 }
  if (-not [string]::IsNullOrWhiteSpace($identity.FileVersion)) {
    $fileMatch=[regex]::Match([string]$identity.FileVersion,'^([0-9]+)\.([0-9]+)\.([0-9]+)(?:\.0)?$',[Text.RegularExpressions.RegexOptions]::CultureInvariant)
    if (-not $fileMatch.Success) { exit 1 }
    [Console]::Out.WriteLine($fileMatch.Groups[1].Value+'.'+$fileMatch.Groups[2].Value+'.'+$fileMatch.Groups[3].Value)
    exit 0
  }
  $stream.Position=0
  $decoder=[Text.Encoding]::ASCII
  $buffer=[byte[]]::new(65536)
  $carry=''
  $versions=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
  while (($count=$stream.Read($buffer,0,$buffer.Length)) -gt 0) {
    $text=$carry+$decoder.GetString($buffer,0,$count)
    foreach ($m in [regex]::Matches($text,'codex-cli[ ]+([0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?)',[Text.RegularExpressions.RegexOptions]::CultureInvariant)) {
      [void]$versions.Add($m.Groups[1].Value)
      if ($versions.Count -gt 1) { exit 1 }
    }
    $carry=$text.Substring([Math]::Max(0,$text.Length-[Math]::Min(256,$text.Length)))
  }
  if ($versions.Count -ne 1) { exit 1 }
  $version=''
  foreach ($item in $versions) { $version=[string]$item; break }
  [Console]::Out.WriteLine($version)
} finally {
  if ($null -ne $stream) { $stream.Dispose() }
}`

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
// Package-manager candidates use static filesystem inspection. Native PE
// candidates are never executed; a fixed system PowerShell process validates
// Authenticode and PE identity while holding the candidate open.
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
	if version, observed, _ := discoverWindowsNativeAgentVersion(cleanHome, connectorName); observed {
		return version
	}

	candidates := windowsAgentVersionCandidatePaths(cleanHome, connectorName)
	for _, candidate := range candidates {
		version, ok := readWindowsAgentVersionCandidate(candidate)
		if ok {
			return version
		}
	}
	return ""
}

func encodeWindowsPowerShellCommand(script string) string {
	encoded := utf16.Encode([]rune(script))
	raw := make([]byte, len(encoded)*2)
	for i, value := range encoded {
		raw[i*2] = byte(value)
		raw[i*2+1] = byte(value >> 8)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

func probeWindowsNativeAgentVersion(connectorName, candidate string) string {
	if err := winpath.RejectReparseChain(candidate); err != nil {
		return ""
	}
	info, err := os.Lstat(candidate)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 512<<20 {
		return ""
	}
	windowsDirectory, err := windows.GetSystemWindowsDirectory()
	if err != nil {
		return ""
	}
	powerShell := filepath.Join(windowsDirectory, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
	if err := winpath.RejectReparseChain(powerShell); err != nil {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), windowsNativeAgentProbeTimeout)
	defer cancel()
	cmd := processutil.CommandContext(
		ctx,
		powerShell,
		"-NoLogo",
		"-NoProfile",
		"-NonInteractive",
		"-ExecutionPolicy", "Bypass",
		"-EncodedCommand", encodeWindowsPowerShellCommand(windowsNativeAgentProbeScript),
	)
	system32 := filepath.Join(windowsDirectory, "System32")
	systemProfile := filepath.Join(system32, "config", "systemprofile")
	systemTemp := filepath.Join(windowsDirectory, "Temp")
	cmd.Env = []string{
		"SystemRoot=" + windowsDirectory,
		"WINDIR=" + windowsDirectory,
		"PATH=" + system32,
		"TEMP=" + systemTemp,
		"TMP=" + systemTemp,
		"USERPROFILE=" + systemProfile,
		"HOMEDRIVE=" + filepath.VolumeName(windowsDirectory),
		"HOMEPATH=" + strings.TrimPrefix(systemProfile, filepath.VolumeName(systemProfile)),
		"DEFENSECLAW_AGENT_CONNECTOR=" + connectorName,
		"DEFENSECLAW_AGENT_CANDIDATE=" + candidate,
	}
	output, err := processutil.CombinedOutputTree(cmd, false)
	if err != nil || len(output) > 256 {
		return ""
	}
	version := strings.TrimSpace(string(output))
	if !validWindowsNativeAgentVersion(version) {
		return ""
	}
	if err := winpath.RejectReparseChain(candidate); err != nil {
		return ""
	}
	return version
}

func validWindowsNativeAgentVersion(version string) bool {
	return len(version) <= 64 && windowsNativeAgentVersionPattern.MatchString(version)
}

func windowsNativeAgentCandidates(profileHome, connectorName string) ([]string, bool) {
	switch connectorName {
	case "claudecode":
		return []string{filepath.Join(profileHome, ".local", "bin", "claude.exe")}, false
	case "codex":
		candidates := make([]string, 0, 2)
		standaloneRoot := filepath.Join(profileHome, ".codex", "packages", "standalone")
		current := filepath.Join(standaloneRoot, "current")
		visibleBin := filepath.Join(profileHome, "AppData", "Local", "Programs", "OpenAI", "Codex", "bin")
		currentInfo, currentErr := os.Lstat(current)
		visibleInfo, visibleErr := os.Lstat(visibleBin)
		currentPresent := currentErr == nil
		visiblePresent := visibleErr == nil
		if visiblePresent && !currentPresent {
			if visibleInfo.Mode()&os.ModeSymlink != 0 || !visibleInfo.IsDir() {
				return candidates, true
			}
			candidates = append(candidates, filepath.Join(visibleBin, "codex.exe"))
		} else if currentPresent || visiblePresent {
			if !visiblePresent ||
				currentInfo.Mode()&os.ModeSymlink == 0 || visibleInfo.Mode()&os.ModeSymlink == 0 {
				return candidates, true
			}
			currentTarget, err := os.Readlink(current)
			if err != nil {
				return candidates, true
			}
			visibleTarget, err := os.Readlink(visibleBin)
			if err != nil {
				return candidates, true
			}
			if !filepath.IsAbs(currentTarget) {
				currentTarget = filepath.Join(filepath.Dir(current), currentTarget)
			}
			if !filepath.IsAbs(visibleTarget) {
				visibleTarget = filepath.Join(filepath.Dir(visibleBin), visibleTarget)
			}
			currentTarget = filepath.Clean(currentTarget)
			visibleTarget = filepath.Clean(visibleTarget)
			releasesRoot := filepath.Join(standaloneRoot, "releases")
			if !strings.EqualFold(filepath.Dir(currentTarget), releasesRoot) {
				return candidates, true
			}
			var binary string
			switch {
			case strings.EqualFold(visibleTarget, filepath.Join(current, "bin")):
				binary = filepath.Join(currentTarget, "bin", "codex.exe")
			case strings.EqualFold(visibleTarget, current):
				binary = filepath.Join(currentTarget, "codex.exe")
			default:
				return candidates, true
			}
			candidates = append(candidates, binary)
		} else if currentErr != nil && !errors.Is(currentErr, os.ErrNotExist) ||
			visibleErr != nil && !errors.Is(visibleErr, os.ErrNotExist) {
			return candidates, true
		}
		runtimeRoot := filepath.Join(profileHome, "AppData", "Local", "OpenAI", "Codex", "bin")
		entries, err := os.ReadDir(runtimeRoot)
		if err != nil {
			return candidates, err != nil && !errors.Is(err, os.ErrNotExist)
		}
		if len(entries) > 256 {
			return candidates, true
		}
		for _, entry := range entries {
			if !entry.IsDir() || !windowsNativeCodexRuntimeLeaf.MatchString(entry.Name()) {
				continue
			}
			candidates = append(candidates, filepath.Join(runtimeRoot, entry.Name(), "codex.exe"))
		}
		return candidates, false
	default:
		return nil, false
	}
}

func discoverWindowsNativeAgentVersion(profileHome, connectorName string) (string, bool, string) {
	candidates, unsafeEnumeration := windowsNativeAgentCandidates(profileHome, connectorName)
	if unsafeEnumeration {
		return "", true, "native candidate enumeration was unsafe"
	}
	observed := false
	invalid := false
	for _, candidate := range candidates {
		_, err := os.Lstat(candidate)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		observed = true
		if err != nil {
			invalid = true
			continue
		}
		version := windowsNativeAgentVersion(connectorName, candidate)
		if version == "" {
			invalid = true
			continue
		}
		if !invalid {
			return version, true, ""
		}
	}
	if invalid {
		return "", true, "native candidate failed identity verification"
	}
	if observed {
		return "", true, "native candidate had no version"
	}
	return "", false, ""
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
//     Native standalone and Codex Desktop runtime candidates are handled by
//     discoverWindowsNativeAgentVersion before these package manifests.
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
	if version, observed, reason := discoverWindowsNativeAgentVersion(filepath.Clean(profileHome), connectorName); observed {
		return version, reason
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
