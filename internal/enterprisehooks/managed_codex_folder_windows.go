// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// The guardian pass reconciles the Codex machine requirements for a
// configured Codex connector, and that reconcile validates the machine-policy
// folder (C:\ProgramData\OpenAI\Codex) without creating it. Setup creates the
// folder and its vendor parent at install. When an administrator or a cleanup
// tool deletes OpenAI or OpenAI\Codex afterwards, the validation failed with
// "cannot find the path" on every pass, the pass stopped before it reached any
// other connector, and nothing ever recreated the folder (GAP-0856).
//
// EnsureWindowsStandaloneCodexMachineFolder gives the guardian the same
// recreation the Cursor and Claude Code folders already get: a missing folder,
// and every missing parent above it, is created through the install-time
// creator of the vendor policy folders (ensureWindowsManagedPolicyDirectory:
// the protected owner and DACL from the first instant, created folders
// recorded for a purge). It never follows a link: a link or a non-folder on
// the path is named once, with the command that fixes it, and nothing is
// created or changed. The caller runs it only for a configured Codex
// connector, so a vendor folder of an unconfigured connector is never created.
// Standalone only; Secure Client is unchanged.

// WindowsCodexMachineFolderEnsure is what the ensure did.
type WindowsCodexMachineFolderEnsure struct {
	// Folder is the Codex machine-policy folder.
	Folder string
	// Created lists the folders it created, parents first.
	Created []string
}

// ErrWindowsCodexMachineFolderUnavailable is wrapped by the error the ensure
// returns when the folder is missing and cannot be recreated.
var ErrWindowsCodexMachineFolderUnavailable = errors.New("the Codex machine-policy folder is missing and was not recreated")

// windowsCodexMachineFolderCreator is the install-time creator of the vendor
// policy folders. Replaceable in tests.
var windowsCodexMachineFolderCreator = ensureWindowsManagedPolicyDirectory

// EnsureWindowsStandaloneCodexMachineFolder recreates a missing Codex
// machine-policy folder (see above). It returns the folders it created, none
// when the folder is already there, and an error that names the problem and the
// command that fixes it when the folder is missing and cannot be recreated.
func EnsureWindowsStandaloneCodexMachineFolder() (WindowsCodexMachineFolderEnsure, error) {
	var result WindowsCodexMachineFolderEnsure
	if !windowsEnterpriseStandaloneProcess() {
		return result, nil
	}
	selector, err := windowsManagedRuntimeSelectorPath("codex")
	if err != nil {
		return result, err
	}
	folder := filepath.Dir(selector)
	result.Folder = folder
	state, link, err := inspectWindowsManagedPolicyDirectoryNoFollow(folder)
	if err != nil {
		return result, windowsCodexMachineFolderWarn(folder, "", err)
	}
	switch state {
	case windowsManagedPolicyDirPlain:
		// A folder that is there but not trusted (a standard user made it after an
		// administrator deleted it, or its owner or protection drifted) is not taken
		// over from the guardian: the reconcile refuses it and stays closed, and an
		// administrator takes it over the documented way, with Setup /repair.
		if trustErr := windowsCodexMachineFolderTrust(folder); trustErr != nil {
			return result, windowsCodexMachineFolderUntrusted(folder, trustErr)
		}
		return result, nil
	case windowsManagedPolicyDirKept:
		return result, windowsCodexMachineFolderWarn(folder, link, nil)
	}
	missing := windowsManagedPolicyMissingChain(folder)
	if err := windowsCodexMachineFolderCreator(folder); err != nil {
		return result, windowsCodexMachineFolderWarn(folder, "", err)
	}
	result.Created = missing
	managed.EmitResilienceEvent(managed.MarkerRepair, map[string]string{
		"path":   folder,
		"reason": "recreated the missing Codex machine-policy folder with the protection Setup gives it",
	})
	return result, nil
}

// windowsCodexMachineFolderTrust is the check the install-time creator makes
// of a folder that already exists: the folder and its existing ancestors are
// DefenseClaw-trusted. Replaceable in tests.
var windowsCodexMachineFolderTrust = func(folder string) error {
	if err := windowsManagedPolicyAncestorTrustCheck(folder); err != nil {
		return err
	}
	return windowsManagedPolicyDirTrustCheck(folder)
}

// windowsCodexMachineFolderUntrusted names, once, an existing Codex
// machine-policy folder that is not trusted, with the fix. The guardian does
// not take it over; the same named error returns on every pass until an
// administrator repairs the deployment with Setup, which does.
func windowsCodexMachineFolderUntrusted(folder string, cause error) error {
	fix := "as an administrator, run " + managed.WindowsSetupCommand("/repair") + " in PowerShell, which takes the folder over with the owner and protection Setup gives it; the guardian does not take over a folder that already exists. " + managed.WindowsSetupSource
	text := fmt.Sprintf("the Codex machine-policy folder %s exists but is not trusted: %v", folder, cause)
	managed.EmitResilienceEventOnce(folder, managed.MarkerBoundary, map[string]string{
		"path":   folder,
		"reason": text,
		"fix":    fix,
	})
	return fmt.Errorf("%w: %s; %s", ErrWindowsCodexMachineFolderUnavailable, text, fix)
}

// windowsManagedPolicyMissingChain lists the folders of path that do not
// exist yet, parents first.
func windowsManagedPolicyMissingChain(path string) []string {
	var missing []string
	for current := filepath.Clean(path); ; current = filepath.Dir(current) {
		if _, err := os.Lstat(current); err == nil {
			break
		}
		missing = append([]string{current}, missing...)
		if parent := filepath.Dir(current); parent == current {
			break
		}
	}
	return missing
}

// windowsCodexMachineFolderWarn names the problem once, with the fix, and
// returns the error the guardian pass reports: the same named text on every
// pass, so the log carries one warning and the retries only repeat the error.
func windowsCodexMachineFolderWarn(folder, link string, cause error) error {
	var text, fix string
	if link != "" {
		fix = fmt.Sprintf("as an administrator, remove the link with: cmd /c rmdir \"%s\" (it removes the link only, not its target); the guardian then recreates the folder on its next pass", link)
		text = fmt.Sprintf("a link or a non-folder sits at %s on the path of the Codex machine-policy folder %s; DefenseClaw does not follow, change or remove it, so the folder cannot be recreated", link, folder)
	} else {
		fix = "as an administrator, run " + managed.WindowsSetupCommand("/repair") + " in PowerShell, or create the folder again. " + managed.WindowsSetupSource
		text = fmt.Sprintf("the Codex machine-policy folder %s is missing and could not be recreated: %v", folder, cause)
	}
	managed.EmitResilienceEventOnce(folder, managed.MarkerBoundary, map[string]string{
		"path":   folder,
		"reason": text,
		"fix":    fix,
	})
	return fmt.Errorf("%w: %s; %s", ErrWindowsCodexMachineFolderUnavailable, text, fix)
}
