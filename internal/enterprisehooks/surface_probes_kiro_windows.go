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

// windowsKiroForms lists profileHome's installed Kiro forms for AssessKiro:
// the kiro-cli (its run copy's version, or unknown before its first run) and
// every Kiro IDE install.
func windowsKiroForms(profileHome string) []KiroForm {
	var forms []KiroForm
	if cli := discoverWindowsKiroCLIVersion(profileHome); cli != "" {
		forms = append(forms, KiroForm{Kind: KiroFormCLI, Version: cli})
	} else if launcher := windowsKiroCLIVersionUnknown(profileHome); launcher != "" {
		forms = append(forms, KiroForm{Kind: KiroFormCLI, Unread: windowsKiroCLIVersionUnknownReason(launcher)})
	}
	return append(forms, windowsKiroIDEForms(profileHome)...)
}

// discoverWindowsKiroAgentVersion returns the version a Kiro row is enrolled
// at: AssessKiro's protected form (a kiro-cli at or above its floor, else an
// IDE at or above the global-hooks floor). Without one it returns the
// kiro-cli's version, so the row's admission refuses and reports it; a CLI
// with no version is reported by windowsKiroCLIVersionUnknown.
func discoverWindowsKiroAgentVersion(profileHome string) string {
	if enroll := AssessKiro(windowsKiroForms(profileHome)).Enroll; enroll != "" {
		return enroll
	}
	return discoverWindowsKiroCLIVersion(profileHome)
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

// windowsKiroIDEForms returns profileHome's Kiro IDE installs, the user's
// own install first: each product.json's version, or, when the file exists
// but cannot be read or names no valid version, an install whose version is
// unknown (JudgeKiroForm: not protected).
func windowsKiroIDEForms(profileHome string) []KiroForm {
	product := filepath.Join("Kiro", "resources", "app", "product.json")
	type candidate struct {
		kind KiroFormKind
		path string
	}
	candidates := []candidate{{KiroFormUserIDE, filepath.Join(profileHome, "AppData", "Local", "Programs", product)}}
	if programFiles, err := winpath.TrustedProgramFiles(); err == nil && programFiles != "" {
		candidates = append(candidates, candidate{KiroFormMachineIDE, filepath.Join(programFiles, product)})
	}
	var forms []KiroForm
	for _, c := range candidates {
		if _, err := os.Lstat(c.path); err != nil {
			continue
		}
		form := KiroForm{Kind: c.kind, Version: readWindowsKiroIDEProductVersion(c.path)}
		if form.Version == "" {
			form.Unread = fmt.Sprintf("Kiro IDE at %s is installed, but its version could not be read", c.path)
		}
		forms = append(forms, form)
	}
	return forms
}

// readWindowsKiroIDEProductVersion returns the version a bounded Kiro IDE
// product.json names, or "".
func readWindowsKiroIDEProductVersion(path string) string {
	data, err := readBoundedWindowsAgentPackageJSON(path)
	if err != nil {
		return ""
	}
	var parsed struct {
		NameShort       string `json:"nameShort"`
		ApplicationName string `json:"applicationName"`
		Version         string `json:"version"`
	}
	if json.Unmarshal(data, &parsed) != nil || parsed.NameShort != "Kiro" || parsed.ApplicationName != "kiro" {
		return ""
	}
	if version := strings.TrimSpace(parsed.Version); isValidWindowsAgentVersion(version) {
		return version
	}
	return ""
}

func windowsKiroCLIBelowHookFloor(version string) string {
	if verdict := JudgeKiroForm(kiroFormFromRowVersion(version)); !verdict.Form.IDE() && verdict.BelowFloor() {
		return verdict.Reason
	}
	return ""
}

// reportKiroCLIBesideIDE records the CLI surface that is not covered even
// though the same row protects a supported IDE (AssessKiro): a kiro-cli below
// the floor sends no hooks from its headless runs, and one whose version is
// unknown is not assumed to be at the floor.
func (c windowsStandaloneRowContext) reportKiroCLIBesideIDE(row *ManifestTarget) {
	if c.report == nil || !strings.EqualFold(strings.TrimSpace(row.Connector), "kiro") || !filepath.IsAbs(row.UserHome) {
		return
	}
	assessment := AssessKiro(windowsKiroForms(filepath.Clean(row.UserHome)))
	if assessment.Enrolled == nil || !assessment.Enrolled.Form.IDE() {
		return // the row's own refusal or kept-row report covers the CLI
	}
	for _, verdict := range assessment.Forms {
		switch {
		case verdict.Form.IDE() || verdict.Protected:
		case verdict.Unknown():
			c.reportAgent(row, "", verdict.Form.Unread, "Kiro IDE "+assessment.Enrolled.Version+
				" is separately eligible for global hooks, but this kiro-cli is not counted as protected until its version is read")
		default:
			c.reportAgent(row, verdict.Version, verdict.Reason, "Kiro IDE "+assessment.Enrolled.Version+
				" is separately eligible for global hooks, but this kiro-cli's non-interactive runs load no hooks")
		}
	}
}

// reportKeptKiroCLIRow reports a kept kiro-cli row whose installed hooks do
// not cover the CLI: one an earlier release enrolled below the floor (its
// headless runs load no hooks), and one enrolled at a version the CLI has not
// confirmed because no run copy names it (an earlier build assumed it,
// GAP-0829). The row stays, so its interactive hooks keep being repaired. A
// row next to a protected IDE is covered by reportKiroCLIBesideIDE.
func (c windowsStandaloneRowContext) reportKeptKiroCLIRow(row *ManifestTarget, version string) {
	if kiroFormFromRowVersion(version).IDE() || !filepath.IsAbs(row.UserHome) {
		return
	}
	home := filepath.Clean(row.UserHome)
	assessment := AssessKiro(windowsKiroForms(home))
	if assessment.Enrolled != nil && assessment.Enrolled.Form.IDE() {
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

// reportKiroIDENotProtected reports every Kiro IDE install AssessKiro does
// not protect: one too old to read the global hooks file, and one whose
// version could not be read. Its agent sessions are not counted as protected
// whether or not the user's kiro-cli is enrolled.
func (c windowsStandaloneRowContext) reportKiroIDENotProtected(row *ManifestTarget) {
	if c.report == nil || !strings.EqualFold(strings.TrimSpace(row.Connector), "kiro") || !filepath.IsAbs(row.UserHome) {
		return
	}
	for _, verdict := range AssessKiro(windowsKiroForms(filepath.Clean(row.UserHome))).Unprotected() {
		if !verdict.Form.IDE() {
			continue
		}
		c.report(UnprotectedAgent{
			User:      c.user,
			SID:       canonicalManifestTargetSID(row.SID),
			Connector: "kiro",
			Version:   verdict.Version,
			Code:      verdict.Code,
			Reason:    verdict.Reason,
		})
	}
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
