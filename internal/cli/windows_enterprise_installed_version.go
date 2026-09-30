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
	"fmt"
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
