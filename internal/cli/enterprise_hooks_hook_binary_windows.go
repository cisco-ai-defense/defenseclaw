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
	"strings"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// An agent such as Claude Code treats a hook command that cannot start as a
// non-blocking error, so while defenseclaw-hook.exe is missing (an antivirus
// quarantine, for example) every tool call runs unchecked. The standalone
// guardian keeps a protected copy of the recorded hook binary in its own
// administrator-only folder and puts it back within one cycle (GAP-0935).

// windowsInstallFileSDDL is the InstallFile contract of the lifecycle:
// SYSTEM and Administrators full control, Users read and execute, protected.
const windowsInstallFileSDDL = "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)"

func init() {
	previous := enterpriseHookAfterWatchReconcile
	enterpriseHookAfterWatchReconcile = func(ctx context.Context, stderr io.Writer, run enterpriseHookReconcileRun) {
		previous(ctx, stderr, run)
		if enterprisehooks.WindowsStandaloneProcess() {
			keepWindowsStandaloneHookBinary(stderr)
		}
	}
}

// keepWindowsStandaloneHookBinary keeps the guardian's copy of the recorded
// hook binary and restores the binary from it when it is missing.
func keepWindowsStandaloneHookBinary(stderr io.Writer) {
	roots, err := winpath.TrustedEnterpriseRoots(managed.ProfileStandalone)
	if err != nil || !strings.HasPrefix(strings.ToLower(filepath.Clean(enterpriseHookManifest)), strings.ToLower(roots.StateRoot)+`\`) {
		return
	}
	want, err := windowsRecordedArtifactHash(roots.MetadataPath, "hook")
	if err != nil || want == "" {
		return
	}
	target := filepath.Join(roots.InstallRoot, "bin", "defenseclaw-hook.exe")
	copyPath := filepath.Join(roots.StateRoot, "hook-guardian", "payload", "defenseclaw-hook.exe")
	restored, err := keepWindowsManagedFileCopy(target, copyPath, want)
	switch {
	case err != nil:
		fmt.Fprintf(stderr, "[hook-guardian] %s\n", err)
	case restored:
		fmt.Fprintf(stderr, "[hook-guardian] restored the missing hook binary %s from the guardian's protected copy (sha256 %s)\n", target, want)
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
// the recorded file (sha256 want), and restores a missing target from a copy
// that still is. It reports whether it restored target.
func keepWindowsManagedFileCopy(target, copyPath, want string) (bool, error) {
	info, err := os.Lstat(target)
	if err == nil {
		if !info.Mode().IsRegular() {
			return false, nil
		}
		if sum, err := windowsFileSHA256Hex(copyPath); err == nil && sum == want {
			return false, nil
		}
		if sum, err := windowsFileSHA256Hex(target); err != nil || sum != want {
			return false, nil
		}
		if err := os.MkdirAll(filepath.Dir(copyPath), 0o700); err != nil {
			return false, fmt.Errorf("keep a protected copy of %s: %w", target, err)
		}
		return false, copyWindowsManagedFile(target, copyPath, "")
	}
	if !errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if sum, err := windowsFileSHA256Hex(copyPath); err != nil || sum != want {
		return false, fmt.Errorf("the hook binary %s is missing and the guardian has no copy of the recorded release; agent hooks cannot start until Setup /repair restores it", target)
	}
	if err := copyWindowsManagedFile(copyPath, target, windowsInstallFileSDDL); err != nil {
		return false, fmt.Errorf("restore the missing hook binary %s: %w", target, err)
	}
	if sum, err := windowsFileSHA256Hex(target); err != nil || sum != want {
		_ = os.Remove(target)
		return false, fmt.Errorf("restore the missing hook binary %s: the restored file does not match the recorded release", target)
	}
	return true, nil
}

// copyWindowsManagedFile copies source to destination through a temporary
// sibling, with the protected access list sddl when it is not empty, and
// renames it into place without replacing a file that appeared meanwhile.
func copyWindowsManagedFile(source, destination, sddl string) error {
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
	if sddl == "" {
		flags |= windows.MOVEFILE_REPLACE_EXISTING
	}
	if err := windows.MoveFileEx(from, to, flags); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	return nil
}

func windowsFileSHA256Hex(path string) (string, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:]), nil
}
