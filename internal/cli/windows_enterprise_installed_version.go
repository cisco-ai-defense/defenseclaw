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

package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// windowsEnterpriseInstalledProductVersion reads the ProductVersion string
// resource of the installed standalone gateway binary.
var windowsEnterpriseInstalledProductVersion = readWindowsEnterpriseInstalledProductVersion

func readWindowsEnterpriseInstalledProductVersion(opts *windowsEnterpriseLifecycleOptions) (string, error) {
	root := ""
	if opts != nil {
		root = strings.TrimSpace(opts.installRoot)
	}
	if root == "" {
		roots, err := winpath.TrustedEnterpriseRoots(managed.ProfileStandalone)
		if err != nil {
			return "", err
		}
		root = roots.InstallRoot
	}
	return windowsFileProductVersion(filepath.Join(root, "bin", "defenseclaw-gateway.exe"))
}

// windowsFileProductVersion returns the first translation's ProductVersion
// string from a PE version resource.
func windowsFileProductVersion(path string) (string, error) {
	size, err := windows.GetFileVersionInfoSize(path, nil)
	if err != nil {
		return "", fmt.Errorf("read the version resource size of %s: %w", path, err)
	}
	if size == 0 || size > 1<<20 {
		return "", fmt.Errorf("the version resource of %s has an unexpected size %d", path, size)
	}
	buffer := make([]byte, size)
	defer runtime.KeepAlive(buffer)
	block := unsafe.Pointer(&buffer[0])
	if err := windows.GetFileVersionInfo(path, 0, size, block); err != nil {
		return "", fmt.Errorf("read the version resource of %s: %w", path, err)
	}
	within := func(pointer unsafe.Pointer, bytes uintptr) bool {
		start := uintptr(block)
		at := uintptr(pointer)
		return pointer != nil && at >= start && at-start <= uintptr(len(buffer)) &&
			bytes <= uintptr(len(buffer))-(at-start)
	}
	var translation unsafe.Pointer
	var length uint32
	if err := windows.VerQueryValue(block, `\VarFileInfo\Translation`, unsafe.Pointer(&translation), &length); err != nil {
		return "", fmt.Errorf("read the version translation of %s: %w", path, err)
	}
	if length < 4 || !within(translation, 4) {
		return "", fmt.Errorf("the version resource of %s has no translation", path)
	}
	language := *(*uint16)(translation)
	codePage := *(*uint16)(unsafe.Add(translation, 2))
	var value unsafe.Pointer
	length = 0
	key := fmt.Sprintf(`\StringFileInfo\%04x%04x\ProductVersion`, language, codePage)
	if err := windows.VerQueryValue(block, key, unsafe.Pointer(&value), &length); err != nil {
		return "", fmt.Errorf("read the product version of %s: %w", path, err)
	}
	if length == 0 || length > 256 || !within(value, uintptr(length)*2) {
		return "", fmt.Errorf("the product version of %s is missing or malformed", path)
	}
	return strings.TrimSpace(windows.UTF16ToString(unsafe.Slice((*uint16)(value), length))), nil
}

// windowsEnterpriseRepairRecordingOptions makes a standalone repair record
// the version of the binaries it keeps. Repair reapplies ACL, service and
// environment invariants to the payload already in place. Started from a
// newer Setup (for example ensure finishing a failed upgrade whose rollback
// restored the older binaries), recording the Setup's own version would
// advance the deployment metadata, the Add/Remove Programs entry and every
// MDM detection rule built on them past the binaries that actually run, so a
// later ensure would stop converging. When the installed version cannot be
// read the options are returned unchanged.
func windowsEnterpriseRepairRecordingOptions(action string, opts *windowsEnterpriseLifecycleOptions) *windowsEnterpriseLifecycleOptions {
	if opts == nil || !strings.EqualFold(strings.TrimSpace(action), "repair") || !windowsEnterpriseStandalone(opts) {
		return opts
	}
	version, err := windowsEnterpriseInstalledProductVersion(opts)
	if restored, ok := windowsEnterprisePendingRestoredVersion(opts); ok {
		// A pending transaction is recovered by restoring its snapshot, so
		// the binaries this repair keeps are the snapshot ones. The binary
		// in place can be the half-replaced new one: recording its version
		// reported 1.0.1811 for restored 1.0.1810 binaries, and the next
		// plan refused the installed CLI as a downgrade (GAP-0767).
		version, err = restored, nil
	}
	version = strings.TrimSpace(version)
	if err != nil || version == "" {
		return opts
	}
	if _, _, ok := parseWindowsEnterpriseVersion(version); !ok {
		return opts
	}
	copied := *opts
	copied.productVersion = version
	return &copied
}

// windowsEnterprisePendingRestoredVersion is the version of the gateway
// binary that the recovery of a pending lifecycle transaction restores: the
// ProductVersion of its copy in the protected transaction snapshot. ok is
// false without a pending transaction, for one that had no gateway binary
// before it (a first install), or when the snapshot cannot be read and
// trusted. A seam for tests.
var windowsEnterprisePendingRestoredVersion = readWindowsEnterprisePendingRestoredVersion

func readWindowsEnterprisePendingRestoredVersion(opts *windowsEnterpriseLifecycleOptions) (string, bool) {
	roots, err := winpath.TrustedEnterpriseRoots(managed.ProfileStandalone)
	if err != nil || strings.TrimSpace(roots.MetadataPath) == "" {
		return "", false
	}
	installRoot := strings.TrimSpace(roots.InstallRoot)
	if opts != nil && strings.TrimSpace(opts.installRoot) != "" {
		installRoot = strings.TrimSpace(opts.installRoot)
	}
	installState := filepath.Dir(filepath.Clean(roots.MetadataPath))
	readTrusted := func(path string) ([]byte, bool) {
		if managed.ValidateTrustedFilePath(path, "lifecycle transaction record") != nil {
			return nil, false
		}
		body, err := readWindowsEnterpriseBoundedFile(path, 4<<20)
		return body, err == nil
	}
	pendingPath := filepath.Join(installState, "pending.json")
	if _, err := os.Lstat(pendingPath); err != nil {
		return "", false
	}
	body, ok := readTrusted(pendingPath)
	if !ok {
		return "", false
	}
	var pending struct {
		Snapshot string `json:"snapshot"`
	}
	if json.Unmarshal(trimWindowsJSONBOM(body), &pending) != nil {
		return "", false
	}
	snapshotPath := filepath.Clean(strings.TrimSpace(pending.Snapshot))
	transactions := filepath.Join(installState, "transactions")
	if !strings.EqualFold(filepath.Dir(filepath.Dir(snapshotPath)), transactions) ||
		!strings.EqualFold(filepath.Base(snapshotPath), "snapshot.json") {
		return "", false
	}
	if body, ok = readTrusted(snapshotPath); !ok {
		return "", false
	}
	var snapshot struct {
		Files []struct {
			Path    string `json:"path"`
			Existed bool   `json:"existed"`
			Backup  string `json:"backup"`
		} `json:"files"`
	}
	if json.Unmarshal(trimWindowsJSONBOM(body), &snapshot) != nil {
		return "", false
	}
	gateway := filepath.Join(installRoot, "bin", "defenseclaw-gateway.exe")
	for _, file := range snapshot.Files {
		if !strings.EqualFold(filepath.Clean(file.Path), gateway) {
			continue
		}
		backup := filepath.Clean(strings.TrimSpace(file.Backup))
		if !file.Existed || !strings.EqualFold(filepath.Dir(backup), filepath.Dir(snapshotPath)) ||
			managed.ValidateTrustedFilePath(backup, "lifecycle transaction snapshot") != nil {
			return "", false
		}
		version, err := windowsFileProductVersion(backup)
		if err != nil {
			return "", false
		}
		if _, _, ok := parseWindowsEnterpriseVersion(strings.TrimSpace(version)); !ok {
			return "", false
		}
		return strings.TrimSpace(version), true
	}
	return "", false
}
