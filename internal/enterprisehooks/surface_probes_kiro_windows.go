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
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// Kiro discovery for the standalone Windows enumerator. Nothing is run.
//
// kiro-cli.exe (%LOCALAPPDATA%\Kiro-Cli) records no version beside itself,
// but each run copies the build to run\chat-cli-<version>.exe, so the
// active version is the run copy whose size matches kiro-cli.exe (the
// highest such version when several match), as for the native Claude
// installer. A kiro-cli that has never run has no copy and so no version.
// Its version is never assumed (a 2.24.1 install would then be enrolled as
// a supported one although its headless runs load no hooks, rel-1-0-4
// GAP-0829): it is reported as not protected, with no row of its own, until
// its first run names the version.
//
// The Kiro IDE reads the global %USERPROFILE%\.kiro\hooks file from
// KiroIDEGlobalHooksFloor. Its version is the resources\app\product.json of
// the per-user install (%LOCALAPPDATA%\Programs\Kiro) or the machine install
// (%ProgramFiles%\Kiro). A user without an admitted kiro-cli version is
// enrolled at the IDE's version, marked with KiroIDEVersionSuffix; an IDE
// below the floor is reported. The profile owner controls these files, so
// each is only a version claim, bounded and validated like a package.json
// probe.

// discoverWindowsKiroAgentVersion returns the version a Kiro row is enrolled
// at: an admitted kiro-cli's, else an IDE at or above the global-hooks floor.
func discoverWindowsKiroAgentVersion(profileHome string) string {
	cli := discoverWindowsKiroCLIVersion(profileHome)
	if cli != "" && windowsKiroCLIBelowHookFloor(cli) == "" {
		return cli
	}
	ide, _ := discoverWindowsKiroIDEVersion(profileHome)
	if ide != "" && !kiroIDEBelowGlobalHooksFloor(ide) {
		return ide + KiroIDEVersionSuffix
	}
	// The unsupported CLI is reported when no IDE can be enrolled; a CLI
	// with no version is reported by windowsKiroCLIVersionUnknown.
	return cli
}

// windowsKiroCLIVersionUnknown returns profileHome's kiro-cli.exe when it is
// installed but no run copy names its version (it has not run since it was
// installed or updated), else "".
func windowsKiroCLIVersionUnknown(profileHome string) string {
	if !filepath.IsAbs(profileHome) || !windowsKiroCLILauncherPresent(profileHome) ||
		discoverWindowsKiroCLIVersion(profileHome) != "" {
		return ""
	}
	return filepath.Join(filepath.Clean(profileHome), "AppData", "Local", "Kiro-Cli", "kiro-cli.exe")
}

// windowsKiroCLIVersionUnknownReason is the unprotected reason of that
// kiro-cli. It names no hook contract (hook_contract_unverified), so status
// reports the deployment's coverage as incomplete.
func windowsKiroCLIVersionUnknownReason(launcher string) string {
	return fmt.Sprintf("%s has no run copy that matches it, so its version is unknown and not verified against a known hook contract; "+
		"kiro-cli records its build in %s when the user starts it, and the next enumeration enrolls or reports that version",
		launcher, filepath.Join(filepath.Dir(launcher), "run"))
}

// windowsKiroCLILauncherPresent reports a regular kiro-cli.exe under a plain
// %LOCALAPPDATA%\Kiro-Cli folder.
func windowsKiroCLILauncherPresent(profileHome string) bool {
	root := filepath.Join(profileHome, "AppData", "Local", "Kiro-Cli")
	if winpath.RejectReparseChain(root) != nil {
		return false
	}
	launcher, err := os.Lstat(filepath.Join(root, "kiro-cli.exe"))
	return err == nil && launcher.Mode().IsRegular()
}

func discoverWindowsKiroCLIVersion(profileHome string) string {
	root := filepath.Join(profileHome, "AppData", "Local", "Kiro-Cli")
	runDir := filepath.Join(root, "run")
	if winpath.RejectReparseChain(runDir) != nil {
		return ""
	}
	launcher, err := os.Lstat(filepath.Join(root, "kiro-cli.exe"))
	if err != nil || !launcher.Mode().IsRegular() {
		return ""
	}
	entries, err := os.ReadDir(runDir)
	if err != nil || len(entries) > windowsNativeClaudeMaxVersionEntries {
		return ""
	}
	best := ""
	for _, entry := range entries {
		name := entry.Name()
		version := strings.TrimSuffix(strings.TrimPrefix(name, "chat-cli-"), ".exe")
		if version == name || !windowsNativeClaudeVersionName(version) || !isValidWindowsAgentVersion(version) {
			continue
		}
		info, err := os.Lstat(filepath.Join(runDir, name))
		if err != nil || !info.Mode().IsRegular() || info.Size() != launcher.Size() {
			continue
		}
		if best == "" || compareWindowsEnterpriseVersion(version, best) > 0 {
			best = version
		}
	}
	return best
}

// discoverWindowsKiroIDEVersion returns the Kiro IDE version installed for
// profileHome and where it was read, the user's own install first.
func discoverWindowsKiroIDEVersion(profileHome string) (string, string) {
	product := filepath.Join("Kiro", "resources", "app", "product.json")
	candidates := []string{filepath.Join(profileHome, "AppData", "Local", "Programs", product)}
	if programFiles, err := winpath.TrustedProgramFiles(); err == nil && programFiles != "" {
		candidates = append(candidates, filepath.Join(programFiles, product))
	}
	for _, candidate := range candidates {
		data, err := readBoundedWindowsAgentPackageJSON(candidate)
		if err != nil {
			continue
		}
		var parsed struct {
			NameShort       string `json:"nameShort"`
			ApplicationName string `json:"applicationName"`
			Version         string `json:"version"`
		}
		if json.Unmarshal(data, &parsed) != nil || parsed.NameShort != "Kiro" || parsed.ApplicationName != "kiro" {
			continue
		}
		if version := strings.TrimSpace(parsed.Version); isValidWindowsAgentVersion(version) {
			return version, candidate
		}
	}
	return "", ""
}

func kiroIDEBelowGlobalHooksFloor(version string) bool {
	return compareStandaloneFloorVersion(connector.NormalizeAgentVersion("kiro", version), KiroIDEGlobalHooksFloor) < 0
}

func windowsKiroCLIBelowHookFloor(version string) string {
	if strings.HasSuffix(strings.TrimSpace(version), KiroIDEVersionSuffix) {
		return ""
	}
	normalized := connector.NormalizeAgentVersion("kiro", version)
	if normalized == "" || compareStandaloneFloorVersion(normalized, connector.KiroCLIHookFloor) >= 0 {
		return ""
	}
	return connector.KiroCLIBelowHookFloorReason(normalized)
}

// reportKiroCLIBesideIDE records the CLI surface that is not covered even
// though the same row can protect a supported IDE: a kiro-cli below the floor
// sends no hooks from its headless runs, and one whose version is unknown is
// not assumed to be at the floor.
func (c windowsStandaloneRowContext) reportKiroCLIBesideIDE(row *ManifestTarget) {
	if c.report == nil || !strings.EqualFold(strings.TrimSpace(row.Connector), "kiro") || !filepath.IsAbs(row.UserHome) {
		return
	}
	home := filepath.Clean(row.UserHome)
	cli := discoverWindowsKiroCLIVersion(home)
	reason := windowsKiroCLIBelowHookFloor(cli)
	consequence := "this kiro-cli's non-interactive runs load no hooks"
	if reason == "" {
		launcher := windowsKiroCLIVersionUnknown(home)
		if launcher == "" {
			return
		}
		reason = windowsKiroCLIVersionUnknownReason(launcher)
		consequence = "this kiro-cli is not counted as protected until its version is read"
	}
	ide, _ := discoverWindowsKiroIDEVersion(home)
	if ide == "" || kiroIDEBelowGlobalHooksFloor(ide) {
		return // the row's own refusal or kept-row report covers the CLI
	}
	c.reportAgent(row, cli, reason, "Kiro IDE "+ide+" is separately eligible for global hooks, but "+consequence)
}

// reportKeptKiroCLIRow reports a kept kiro-cli row whose installed hooks do
// not cover the CLI: one an earlier release enrolled below the floor (its
// headless runs load no hooks), and one enrolled at a version the CLI has not
// confirmed because no run copy names it (an earlier build assumed it,
// GAP-0829). The row stays, so its interactive hooks keep being repaired. A
// row of a supported IDE is covered by reportKiroCLIBesideIDE.
func (c windowsStandaloneRowContext) reportKeptKiroCLIRow(row *ManifestTarget, version string) {
	if strings.HasSuffix(strings.TrimSpace(version), KiroIDEVersionSuffix) || !filepath.IsAbs(row.UserHome) {
		return
	}
	home := filepath.Clean(row.UserHome)
	if ide, _ := discoverWindowsKiroIDEVersion(home); ide != "" && !kiroIDEBelowGlobalHooksFloor(ide) {
		return
	}
	if launcher := windowsKiroCLIVersionUnknown(home); launcher != "" {
		c.reportAgent(row, version, windowsKiroCLIVersionUnknownReason(launcher), fmt.Sprintf(
			"the row stays enrolled at %s, which this kiro-cli has not confirmed, so its hooks stay installed but it is not counted as protected", version))
		return
	}
	if reason := windowsKiroCLIBelowHookFloor(version); reason != "" {
		c.reportAgent(row, version, reason,
			"an earlier enrollment keeps its interactive hooks installed, but this CLI's non-interactive runs do not load them")
	}
}

// reportKiroIDEBelowFloor reports a Kiro IDE too old to read the global
// hooks file: its agent sessions run without DefenseClaw hooks whether or
// not the user's kiro-cli is enrolled.
func (c windowsStandaloneRowContext) reportKiroIDEBelowFloor(row *ManifestTarget) {
	if c.report == nil || !strings.EqualFold(strings.TrimSpace(row.Connector), "kiro") || !filepath.IsAbs(row.UserHome) {
		return
	}
	ide, _ := discoverWindowsKiroIDEVersion(filepath.Clean(row.UserHome))
	if ide == "" || !kiroIDEBelowGlobalHooksFloor(ide) {
		return
	}
	consequence := "its agent sessions run without DefenseClaw hooks"
	if cli := discoverWindowsKiroCLIVersion(filepath.Clean(row.UserHome)); cli != "" && windowsKiroCLIBelowHookFloor(cli) == "" {
		consequence += "; kiro-cli " + cli + " remains eligible for enrollment"
	}
	c.report(UnprotectedAgent{
		User:      c.user,
		SID:       canonicalManifestTargetSID(row.SID),
		Connector: "kiro",
		Version:   ide,
		Code:      UnprotectedCodeKiroIDEBelowGlobalHooksFloor,
		Reason: fmt.Sprintf("Kiro IDE %s is below %s, the first build that reads the global %%USERPROFILE%%\\.kiro\\hooks file, so %s; update Kiro IDE",
			ide, KiroIDEGlobalHooksFloor, consequence),
	})
}

// windowsKiroInstalled returns the file that shows a Kiro install whose
// version discovery can fail, or "": kiro-cli.exe before its first run (the
// run folder names the version) and the Kiro IDE (its product.json).
func windowsKiroInstalled(profileHome string) string {
	product := filepath.Join("Kiro", "resources", "app", "product.json")
	candidates := []string{
		filepath.Join(profileHome, "AppData", "Local", "Kiro-Cli", "kiro-cli.exe"),
		filepath.Join(profileHome, "AppData", "Local", "Programs", product),
	}
	if programFiles, err := winpath.TrustedProgramFiles(); err == nil {
		candidates = append(candidates, filepath.Join(programFiles, product))
	}
	for _, candidate := range candidates {
		if info, err := os.Lstat(candidate); err == nil && info.Mode().IsRegular() {
			return candidate
		}
	}
	return ""
}
