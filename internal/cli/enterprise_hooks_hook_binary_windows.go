//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// An agent such as Claude Code treats a hook command that cannot start as a
// non-blocking error, so while defenseclaw-hook.exe is missing (an antivirus
// quarantine, for example), empty or not the recorded release every tool
// call runs unchecked. The standalone guardian keeps a protected copy of the
// recorded hook binary in its own administrator-only folder and puts it back
// before each reconcile, which fails on the missing file, and within
// windowsHookBinaryCheckInterval between reconciles (GAP-0935, GAP-0680).
// Setup stops the guardian before it replaces the binaries, so a newer
// release is never taken for a damaged one.

// windowsInstallFileSDDL is the InstallFile contract of the lifecycle:
// SYSTEM and Administrators full control, Users read and execute, protected.
const windowsInstallFileSDDL = "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)"

func init() {
	previousBefore := enterpriseHookBeforeWatchReconcile
	enterpriseHookBeforeWatchReconcile = func(stderr io.Writer) {
		previousBefore(stderr)
		if enterprisehooks.WindowsStandaloneProcess() {
			keepWindowsStandaloneHookBinary(stderr, false)
			keepWindowsStandaloneClaudeDropIn(stderr)
		}
	}
	previous := enterpriseHookAfterWatchReconcile
	enterpriseHookAfterWatchReconcile = func(ctx context.Context, stderr io.Writer, run enterpriseHookReconcileRun) {
		previous(ctx, stderr, run)
		if enterprisehooks.WindowsStandaloneProcess() {
			removeWindowsStandaloneReplacementCopies(stderr)
		}
	}
}

// windowsHookBinaryCheckInterval is how often the guardian checks, between
// reconciles, that the hook binary is still in place.
var windowsHookBinaryCheckInterval = 5 * time.Second

// windowsHookBinaryMu serializes the restore between the check and the
// reconcile; windowsHookBinaryLastErr keeps the check from logging the same
// failure every interval.
var (
	windowsHookBinaryMu      sync.Mutex
	windowsHookBinaryLastErr string
)

// watchWindowsStandaloneHookBinary restores a damaged hook binary, and an
// edited or deleted Claude Code drop-in, within one check interval for the
// life of the guardian watch loop.
func watchWindowsStandaloneHookBinary(ctx context.Context, stderr io.Writer) {
	if !enterprisehooks.WindowsStandaloneProcess() {
		return
	}
	ticker := time.NewTicker(windowsHookBinaryCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			keepWindowsStandaloneHookBinary(stderr, true)
			keepWindowsStandaloneClaudeDropIn(stderr)
		}
	}
}

// windowsReplacementCopyPattern is the copy an upgrade keeps of a binary a
// running program still used: <binary>.backup.<32 hex>.
var windowsReplacementCopyPattern = regexp.MustCompile(`^(?i:defenseclaw[a-z0-9-]*\.exe)\.backup\.[0-9a-f]{32}$`)

// removeWindowsStandaloneReplacementCopies removes, as soon as no program
// runs it any more, the copy an upgrade kept of a binary an editor's ACP
// thread still ran. Only an upgrade or uninstall used to remove it, so a
// no-op ensure and a guardian restart left it in bin (GAP-0934, GAP-0937).
func removeWindowsStandaloneReplacementCopies(stderr io.Writer) {
	roots, err := winpath.TrustedEnterpriseRoots(managed.ProfileStandalone)
	if err != nil || !strings.HasPrefix(strings.ToLower(filepath.Clean(enterpriseHookManifest)), strings.ToLower(roots.StateRoot)+`\`) {
		return
	}
	for _, removed := range removeWindowsReplacementCopies(filepath.Join(roots.InstallRoot, "bin")) {
		fmt.Fprintf(stderr, "[hook-guardian] removed %s, which no program runs any more\n", removed)
	}
}

// removeWindowsReplacementCopies deletes each replacement copy in dir that
// no program holds open and returns the ones it removed.
func removeWindowsReplacementCopies(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var removed []string
	for _, entry := range entries {
		if !windowsReplacementCopyPattern.MatchString(entry.Name()) || !entry.Type().IsRegular() {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		if err := os.Remove(path); err == nil {
			removed = append(removed, path)
		}
	}
	return removed
}

// keepWindowsStandaloneHookBinary keeps the guardian copy of the recorded
// hook binary and restores the binary from it when it is damaged. With
// onlyWhenDamaged it does not refresh the copy.
func keepWindowsStandaloneHookBinary(stderr io.Writer, onlyWhenDamaged bool) {
	roots, err := winpath.TrustedEnterpriseRoots(managed.ProfileStandalone)
	if err != nil || !strings.HasPrefix(strings.ToLower(filepath.Clean(enterpriseHookManifest)), strings.ToLower(roots.StateRoot)+`\`) {
		return
	}
	target := filepath.Join(roots.InstallRoot, "bin", "defenseclaw-hook.exe")
	windowsHookBinaryMu.Lock()
	defer windowsHookBinaryMu.Unlock()
	want, err := windowsRecordedArtifactHash(roots.MetadataPath, "hook")
	if err != nil || want == "" {
		return
	}
	copyPath := filepath.Join(roots.StateRoot, "hook-guardian", "payload", "defenseclaw-hook.exe")
	damage, err := keepWindowsManagedFileCopy(target, copyPath, want, !onlyWhenDamaged)
	if err != nil {
		if message := err.Error(); message != windowsHookBinaryLastErr {
			windowsHookBinaryLastErr = message
			fmt.Fprintf(stderr, "[hook-guardian] %s\n", message)
		}
		return
	}
	windowsHookBinaryLastErr = ""
	if damage != "" {
		fmt.Fprintf(stderr, "[hook-guardian] tamper: restored the hook binary %s, which was %s, from the guardian's protected copy (sha256 %s)\n", target, damage, want)
	}
}

// windowsRestoreClaudeDropIn puts DefenseClaw's Claude Code drop-in back
// from its ownership record; tests replace it.
var windowsRestoreClaudeDropIn = enterprisehooks.RestoreWindowsClaudeManagedPolicyDrift

// windowsClaudeDropInLastErr keeps the drop-in check from logging the same
// failure every interval.
var windowsClaudeDropInLastErr string

// keepWindowsStandaloneClaudeDropIn puts DefenseClaw's own Claude Code
// drop-in (90-defenseclaw.json) back when it was edited or deleted, as the
// Unix guardian does (GAP-1178). The Windows guardian left it changed, so
// every enrolled user's Claude Code prompt failed closed and the reconcile
// and Setup /repair refused the file as an administrator edit (GAP-1108).
func keepWindowsStandaloneClaudeDropIn(stderr io.Writer) {
	roots, err := winpath.TrustedEnterpriseRoots(managed.ProfileStandalone)
	if err != nil || !strings.HasPrefix(strings.ToLower(filepath.Clean(enterpriseHookManifest)), strings.ToLower(roots.StateRoot)+`\`) {
		return
	}
	windowsHookBinaryMu.Lock()
	defer windowsHookBinaryMu.Unlock()
	restored, err := windowsRestoreClaudeDropIn()
	if err != nil {
		if message := err.Error(); message != windowsClaudeDropInLastErr {
			windowsClaudeDropInLastErr = message
			fmt.Fprintf(stderr, "[hook-guardian] %s\n", message)
		}
		return
	}
	windowsClaudeDropInLastErr = ""
	if restored {
		fmt.Fprintf(stderr, "[hook-guardian] tamper: put back DefenseClaw's Claude Code drop-in, which was changed or removed outside DefenseClaw\n")
	}
}

// windowsRecordedArtifactHash reads the SHA-256 the deployment metadata
// records for an artifact.
func windowsRecordedArtifactHash(metadataPath, name string) (string, error) {
	body, err := readWindowsEnterpriseBoundedFile(metadataPath, 1<<20)
	if err != nil {
		return "", err
	}
	var metadata struct {
		Hashes map[string]string `json:"hashes"`
	}
	if err := json.Unmarshal(trimWindowsJSONBOM(body), &metadata); err != nil {
		return "", err
	}
	return strings.ToLower(strings.TrimSpace(metadata.Hashes[name])), nil
}

// keepWindowsManagedFileCopy refreshes copyPath from target while target is
// the recorded file (sha256 want) and refresh is set, and restores target
// from a copy that still is when target is missing, empty or another file.
// It reports what was wrong with the target it restored, or "".
func keepWindowsManagedFileCopy(target, copyPath, want string, refresh bool) (string, error) {
	damage := ""
	info, err := os.Lstat(target)
	switch {
	case errors.Is(err, os.ErrNotExist):
		damage = "missing"
	case err != nil || !info.Mode().IsRegular():
		return "", nil
	case info.Size() == 0:
		damage = "empty (0 bytes)"
	default:
		sum, err := windowsFileSHA256Hex(target)
		if err != nil {
			return "", nil
		}
		if sum != want {
			damage = "not the recorded release (hash mismatch: sha256 " + sum + ")"
			break
		}
		if !refresh {
			return "", nil
		}
		if sum, err := windowsFileSHA256Hex(copyPath); err == nil && sum == want {
			return "", nil
		}
		if err := os.MkdirAll(filepath.Dir(copyPath), 0o700); err != nil {
			return "", fmt.Errorf("keep a protected copy of %s: %w", target, err)
		}
		return "", copyWindowsManagedFile(target, copyPath, "", true)
	}
	if sum, err := windowsFileSHA256Hex(copyPath); err != nil || sum != want {
		return "", fmt.Errorf("the hook binary %s is %s and the guardian has no copy of the recorded release; agents run tool calls without DefenseClaw until Setup /repair restores it", target, damage)
	}
	// A missing binary is put back without replacing one that appeared
	// meanwhile; a damaged one is replaced.
	if err := copyWindowsManagedFile(copyPath, target, windowsInstallFileSDDL, damage != "missing"); err != nil {
		return "", fmt.Errorf("restore the hook binary %s, which is %s: %w", target, damage, err)
	}
	if sum, err := windowsFileSHA256Hex(target); err != nil || sum != want {
		_ = os.Remove(target)
		return "", fmt.Errorf("restore the hook binary %s: the restored file does not match the recorded release", target)
	}
	return damage, nil
}

// copyWindowsManagedFile copies source to destination through a temporary
// sibling, with the protected access list sddl when it is not empty, and
// renames it into place, replacing a file already there only with replace.
func copyWindowsManagedFile(source, destination, sddl string, replace bool) error {
	body, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	suffix := make([]byte, 8)
	if _, err := rand.Read(suffix); err != nil {
		return err
	}
	temporary := destination + ".restore-" + hex.EncodeToString(suffix)
	if err := os.WriteFile(temporary, body, 0o600); err != nil {
		return err
	}
	if sddl != "" {
		descriptor, err := windows.SecurityDescriptorFromString(sddl)
		if err == nil {
			var dacl *windows.ACL
			if dacl, _, err = descriptor.DACL(); err == nil {
				err = windows.SetNamedSecurityInfo(temporary, windows.SE_FILE_OBJECT,
					windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
			}
		}
		if err != nil {
			_ = os.Remove(temporary)
			return err
		}
	}
	from, err := windows.UTF16PtrFromString(temporary)
	if err != nil {
		_ = os.Remove(temporary)
		return err
	}
	to, err := windows.UTF16PtrFromString(destination)
	if err != nil {
		_ = os.Remove(temporary)
		return err
	}
	flags := uint32(windows.MOVEFILE_WRITE_THROUGH)
	if replace {
		flags |= windows.MOVEFILE_REPLACE_EXISTING
	}
	if err := windows.MoveFileEx(from, to, flags); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	return nil
}

func windowsFileSHA256Hex(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
