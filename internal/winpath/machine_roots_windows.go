// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package winpath

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	windowsCurrentVersionKey = `SOFTWARE\Microsoft\Windows\CurrentVersion`
	windowsShellFoldersKey   = `SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
)

// TrustedMachineRoots contains canonical machine-wide Windows roots read from
// protected 64-bit HKLM registration. It never consults the inherited process
// environment.
type TrustedMachineRoots struct {
	ProgramFiles    string
	ProgramFilesX86 string
	ProgramData     string
}

// ResolveTrustedMachineRoots reads fixed 64-bit machine registration.
// SHGetKnownFolderPath can fail after a deployment launcher deliberately
// clears the inherited environment, while these REG_SZ values remain
// available to the same process.
func ResolveTrustedMachineRoots() (TrustedMachineRoots, error) {
	var roots TrustedMachineRoots
	currentVersion, err := registry.OpenKey(
		registry.LOCAL_MACHINE,
		windowsCurrentVersionKey,
		registry.QUERY_VALUE|registry.WOW64_64KEY,
	)
	if err != nil {
		return roots, fmt.Errorf("open trusted 64-bit Program Files registration: %w", err)
	}
	defer currentVersion.Close()

	roots.ProgramFiles, err = readTrustedMachineRoot(
		currentVersion,
		"ProgramFilesDir",
		"Program Files",
	)
	if err != nil {
		return TrustedMachineRoots{}, err
	}
	roots.ProgramFilesX86, err = readTrustedMachineRoot(
		currentVersion,
		"ProgramFilesDir (x86)",
		"Program Files (x86)",
	)
	if err != nil {
		return TrustedMachineRoots{}, err
	}

	shellFolders, err := registry.OpenKey(
		registry.LOCAL_MACHINE,
		windowsShellFoldersKey,
		registry.QUERY_VALUE|registry.WOW64_64KEY,
	)
	if err != nil {
		return TrustedMachineRoots{}, fmt.Errorf(
			"open trusted 64-bit ProgramData registration: %w",
			err,
		)
	}
	defer shellFolders.Close()
	roots.ProgramData, err = readTrustedMachineRoot(
		shellFolders,
		"Common AppData",
		"ProgramData",
	)
	if err != nil {
		return TrustedMachineRoots{}, err
	}
	return roots, nil
}

// TrustedProgramFiles resolves the protected machine-wide Program Files root.
func TrustedProgramFiles() (string, error) {
	key, err := registry.OpenKey(
		registry.LOCAL_MACHINE,
		windowsCurrentVersionKey,
		registry.QUERY_VALUE|registry.WOW64_64KEY,
	)
	if err != nil {
		return "", fmt.Errorf("open trusted 64-bit Program Files registration: %w", err)
	}
	defer key.Close()
	return readTrustedMachineRoot(key, "ProgramFilesDir", "Program Files")
}

// TrustedProgramData resolves the protected machine-wide ProgramData root.
func TrustedProgramData() (string, error) {
	key, err := registry.OpenKey(
		registry.LOCAL_MACHINE,
		windowsShellFoldersKey,
		registry.QUERY_VALUE|registry.WOW64_64KEY,
	)
	if err != nil {
		return "", fmt.Errorf("open trusted 64-bit ProgramData registration: %w", err)
	}
	defer key.Close()
	return readTrustedMachineRoot(key, "Common AppData", "ProgramData")
}

func readTrustedMachineRoot(key registry.Key, valueName, label string) (string, error) {
	value, valueType, err := key.GetStringValue(valueName)
	if err != nil {
		return "", fmt.Errorf("read trusted %s machine registration: %w", label, err)
	}
	// Expanding REG_EXPAND_SZ would reintroduce the attacker-controlled process
	// environment at the exact boundary this resolver is intended to avoid.
	if valueType != registry.SZ {
		return "", fmt.Errorf("trusted %s machine registration is not REG_SZ", label)
	}
	return ValidateTrustedMachineRoot(value, label)
}

// ValidateTrustedMachineRoot applies the fail-closed syntax, mounted-volume,
// existence, and reparse-chain contract used for protected machine roots.
func ValidateTrustedMachineRoot(value, label string) (string, error) {
	if value == "" || strings.TrimSpace(value) != value || strings.Contains(value, "%") {
		return "", fmt.Errorf(
			"trusted %s machine root is empty, padded, or environment-expanded",
			label,
		)
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return "", fmt.Errorf("trusted %s machine root contains a control character", label)
		}
	}
	if strings.Contains(value, "/") {
		return "", fmt.Errorf("trusted %s machine root is not a canonical Windows path", label)
	}
	clean := filepath.Clean(value)
	volume := filepath.VolumeName(clean)
	if clean != value || !filepath.IsAbs(clean) || len(clean) < 3 || clean[2] != '\\' ||
		len(volume) != 2 || volume[1] != ':' || !isASCIIDriveLetter(volume[0]) ||
		strings.HasPrefix(clean, `\\`) || strings.HasPrefix(clean, `\\?\`) ||
		strings.HasPrefix(clean, `\\.\`) || strings.Contains(clean[2:], ":") {
		return "", fmt.Errorf(
			"trusted %s machine root must be canonical local drive-letter syntax: %s",
			label,
			clean,
		)
	}
	if _, err := ValidateFixedNTFSMountedPath(clean); err != nil {
		return "", fmt.Errorf("trusted %s machine root is not on fixed mounted NTFS: %w", label, err)
	}
	for current := clean; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil {
			return "", fmt.Errorf("inspect trusted %s machine root: %w", label, err)
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("trusted %s machine root is not a regular directory: %s", label, current)
		}
		extended, err := Extended(current)
		if err != nil {
			return "", fmt.Errorf("encode trusted %s machine root: %w", label, err)
		}
		pathPtr, err := windows.UTF16PtrFromString(extended)
		if err != nil {
			return "", fmt.Errorf("encode trusted %s machine root: %w", label, err)
		}
		attributes, err := windows.GetFileAttributes(pathPtr)
		if err != nil {
			return "", fmt.Errorf("inspect trusted %s machine root attributes: %w", label, err)
		}
		if attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return "", fmt.Errorf("trusted %s machine root traverses a reparse point: %s", label, current)
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
	}
	return clean, nil
}
