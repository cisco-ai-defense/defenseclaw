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
// installer. A kiro-cli that has never run has no copy: it is enrolled at
// the standalone floor until its first run names the version.
//
// The Kiro IDE reads the global %USERPROFILE%\.kiro\hooks file from
// KiroIDEGlobalHooksFloor. Its version is the resources\app\product.json of
// the per-user install (%LOCALAPPDATA%\Programs\Kiro) or the machine install
// (%ProgramFiles%\Kiro). A user without a readable kiro-cli version is
// enrolled at the IDE's version, marked with KiroIDEVersionSuffix; an IDE
// below the floor is reported. The profile owner controls these files, so
// each is only a version claim, bounded and validated like a package.json
// probe.

// discoverWindowsKiroAgentVersion returns the version a Kiro row is enrolled
// at: kiro-cli's, else an IDE at or above the global-hooks floor.
func discoverWindowsKiroAgentVersion(profileHome string) string {
	if cli := discoverWindowsKiroCLIVersion(profileHome); cli != "" {
		return cli
	}
	ide, _ := discoverWindowsKiroIDEVersion(profileHome)
	if ide != "" && !kiroIDEBelowGlobalHooksFloor(ide) {
		return ide + KiroIDEVersionSuffix
	}
	// A kiro-cli that has never run names no version yet. Enroll it at the
	// standalone floor so its first chat already runs with the DefenseClaw
	// agent and hooks; the run copy names the real version on the next
	// cycle, which then re-admits or reports it.
	if windowsKiroCLILauncherPresent(profileHome) {
		return standaloneNotGatedAgentFloor("kiro")
	}
	return ""
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
	if cli := discoverWindowsKiroCLIVersion(filepath.Clean(row.UserHome)); cli != "" {
		consequence += "; kiro-cli " + cli + " stays enrolled"
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
