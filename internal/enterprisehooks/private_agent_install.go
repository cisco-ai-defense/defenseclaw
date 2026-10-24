// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"encoding/json"
	"path"
	"sort"
	"strings"
)

// PrivateAgentInstall is static evidence of one agent copy an enrolled
// account can run: in its home, in a version manager, in a machine npm
// prefix or a native installer's version directory. It is deliberately
// separate from the selected version in a manifest row: a supported copy
// must never hide an older copy the user can launch.
//
// Each copy is identified by the real path its package or executable
// resolves to, so one copy reached through a link, an equivalent spelling
// or two prefixes that share a directory is reported once.
type PrivateAgentInstall struct {
	Connector  string `json:"connector"`
	Version    string `json:"version,omitempty"`
	Path       string `json:"path,omitempty"`
	Incomplete bool   `json:"incomplete,omitempty"`
	// Skipped names, for an incomplete entry, the part of the scan that
	// could not be finished (a PrivateInstallSkipped* code), so status
	// says what was not inspected and why instead of truncating silently.
	Skipped string `json:"skipped,omitempty"`
	// Untrusted marks a copy in a location another account can change: its
	// package metadata cannot prove the version, so the copy is reported
	// as unverified whatever it claims.
	Untrusted bool `json:"untrusted,omitempty"`
}

const privateAgentInstallMaxEntries = 1024
const privateAgentInstallMaxFindings = 64
const PrivateAgentInstallMaxFindings = privateAgentInstallMaxFindings

// privateAgentInstallMaxVersionDirs bounds the installed Node versions (or
// native release directories) the separate-copy scan inspects per version
// manager or installer. Selecting the hook contract's version reads only
// the newest few; the scan reads every one up to this bound and reports
// the scan incomplete when a manager holds more.
const privateAgentInstallMaxVersionDirs = 64

// The parts of the separate-copy scan that can be left unfinished.
const (
	PrivateInstallSkippedHome            = "home_unreadable"
	PrivateInstallSkippedVersionManagers = "version_manager_limit"
	PrivateInstallSkippedNativeVersions  = "native_versions_limit"
	PrivateInstallSkippedFindings        = "finding_limit"
	PrivateInstallSkippedLocation        = "location_unreadable"
	PrivateInstallSkippedOutsideRoots    = "path_outside_scan_roots"
	PrivateInstallSkippedUnresolved      = "account_not_inspected"
)

var privateInstallSkippedText = map[string]string{
	PrivateInstallSkippedHome:            "the account's home could not be listed within the scan bound",
	PrivateInstallSkippedVersionManagers: "a Node version manager holds more installed versions than the scan inspects",
	PrivateInstallSkippedNativeVersions:  "a native installer or Homebrew cask holds more releases than the scan inspects",
	PrivateInstallSkippedFindings:        "the account has more unsupported agent copies than the record holds",
	PrivateInstallSkippedLocation:        "an install location could not be read safely",
	PrivateInstallSkippedOutsideRoots:    "discovery named a copy outside the locations DefenseClaw scans",
	PrivateInstallSkippedUnresolved:      "the enrolled account could not be inspected this cycle",
}

// KnownPrivateInstallSkipped returns code when it is a PrivateInstallSkipped*
// code, else "". The root parent keeps only known codes from the per-user
// worker's user-influenced answer.
func KnownPrivateInstallSkipped(code string) string {
	if _, ok := privateInstallSkippedText[code]; ok {
		return code
	}
	return ""
}

func privateInstallIncompleteReason(skipped string) string {
	why := ""
	if text := privateInstallSkippedText[skipped]; text != "" {
		why = " (" + text + ")"
	}
	return "the bounded scan of this account's private agent installs was incomplete" + why +
		"; use application control to exclude unapproved agent binaries"
}

const privateInstallUntrustedReason = "another account can change this copy, so its version cannot be verified; " +
	"this copy may ignore managed hooks or the documented version floor, so its tool calls are not protected"

func privateInstallReason(connector, version string) string {
	if version == "" {
		return "the installed agent's version could not be read, so its managed hook contract cannot be verified"
	}
	if refused := privateInstallContractReason(connector, version); refused != "" {
		return refused + "; this copy may ignore managed hooks or the documented version floor, so its tool calls are not protected"
	}
	return ""
}

// privateInstallUnprotected is the unprotected-agents entry for one scan
// finding, without its account; ok is false for a supported copy.
func privateInstallUnprotected(install PrivateAgentInstall) (agent UnprotectedAgent, ok bool) {
	if install.Incomplete {
		return UnprotectedAgent{Connector: install.Connector, Code: UnprotectedCodeInstallScanIncomplete,
			Reason: privateInstallIncompleteReason(install.Skipped)}, true
	}
	reason := privateInstallReason(install.Connector, install.Version)
	if install.Untrusted {
		reason = privateInstallUntrustedReason
		install.Version = ""
	}
	if reason == "" {
		return UnprotectedAgent{}, false
	}
	return UnprotectedAgent{Connector: install.Connector, Version: install.Version, InstallPath: install.Path,
		Code: UnprotectedCodeHookContractUnverified, Reason: reason}, true
}

// privateInstallScan collects one account's findings. seen holds the
// identity of every copy already judged; incomplete the connectors whose
// scan was left unfinished, with the first reason.
type privateInstallScan struct {
	seen       map[string]bool
	found      []PrivateAgentInstall
	incomplete map[string]string
	order      []string
	full       bool
}

func newPrivateInstallScan() *privateInstallScan {
	return &privateInstallScan{seen: map[string]bool{}, incomplete: map[string]string{}}
}

// judge reports whether the copy with identity is new, recording it.
func (s *privateInstallScan) judge(identity string) bool {
	if s.seen[identity] {
		return false
	}
	s.seen[identity] = true
	return true
}

func (s *privateInstallScan) add(install PrivateAgentInstall) {
	if s.full {
		return
	}
	if len(s.found) >= privateAgentInstallMaxFindings {
		s.full = true
		s.skip(install.Connector, PrivateInstallSkippedFindings)
		return
	}
	s.found = append(s.found, install)
}

func (s *privateInstallScan) skip(connector, code string) {
	if _, known := s.incomplete[connector]; known {
		return
	}
	s.incomplete[connector] = code
	s.order = append(s.order, connector)
}

func (s *privateInstallScan) skipAll(connectors []string, code string) {
	for _, connector := range connectors {
		s.skip(connector, code)
	}
}

// result lists the copies found, then one incomplete entry per connector
// whose scan was left unfinished.
func (s *privateInstallScan) result() []PrivateAgentInstall {
	out := append([]PrivateAgentInstall(nil), s.found...)
	for _, connector := range s.order {
		out = append(out, PrivateAgentInstall{Connector: connector, Incomplete: true, Skipped: s.incomplete[connector]})
	}
	return out
}

func privateInstallConnectors(names []string, known func(string) bool) []string {
	var out []string
	seen := map[string]bool{}
	for _, name := range names {
		name = strings.ToLower(strings.TrimSpace(name))
		if known(name) && !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	return out
}

// privateNPMEntryPoints are the files each agent's npm package starts from,
// relative to the package: Claude Code's cli.js (to 2.1.112) or native
// bin/claude.exe (from 2.1.113), Codex's bin/codex.js, and Copilot's
// npm-loader.js (index.js in early releases). The targets of the package's
// own "bin" field count too: npm links those. A package folder with none of
// them is leftover metadata, not a copy the account can run.
var privateNPMEntryPoints = map[string][]string{
	"claudecode": {"cli.js", "bin/claude.exe"},
	"codex":      {"bin/codex.js"},
	"copilot":    {"npm-loader.js", "index.js"},
}

// privateNPMMaxBinTargets bounds the "bin" targets read from one package.
const privateNPMMaxBinTargets = 16

// privateNPMEntries lists the entry points to look for in a connector's
// package whose package.json holds manifest (nil when it has none): the
// known ones, then each "bin" target (a string, or a map of command names
// to files) that stays inside the package, slash-separated.
func privateNPMEntries(connector string, manifest []byte) []string {
	entries := append([]string(nil), privateNPMEntryPoints[connector]...)
	var parsed struct {
		Bin json.RawMessage `json:"bin"`
	}
	if len(manifest) == 0 || json.Unmarshal(manifest, &parsed) != nil || len(parsed.Bin) == 0 {
		return entries
	}
	var targets []string
	var one string
	var named map[string]string
	switch {
	case json.Unmarshal(parsed.Bin, &one) == nil:
		targets = []string{one}
	case json.Unmarshal(parsed.Bin, &named) == nil:
		for _, target := range named {
			targets = append(targets, target)
		}
		sort.Strings(targets)
	}
	seen := map[string]bool{}
	for _, entry := range entries {
		seen[entry] = true
	}
	added := 0
	for _, target := range targets {
		clean := path.Clean(strings.ReplaceAll(strings.TrimSpace(target), `\`, "/"))
		if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || path.IsAbs(clean) ||
			strings.ContainsAny(clean, ":\x00") || seen[clean] {
			continue
		}
		if added == privateNPMMaxBinTargets {
			break
		}
		seen[clean] = true
		entries = append(entries, clean)
		added++
	}
	return entries
}
