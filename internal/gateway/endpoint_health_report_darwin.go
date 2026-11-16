// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package gateway

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
)

// endpointHealthReceiptDir holds the macOS installer package receipts.
var endpointHealthReceiptDir = "/var/db/receipts"

// endpointHealthAVCReceiptPrefixes and endpointHealthAVCReceiptMarkers are
// the candidate rule for the Secure Client AVC package receipt.
//
// TO BE CONFIRMED ON A macOS VM with Secure Client AVC installed: the AVC
// package identifier is not known. The rule accepts a Secure Client receipt
// id (one of the prefixes) that contains "avc" or "agentic" and does not
// contain "defenseclaw". Replace it with the exact identifier once seen.
var (
	endpointHealthAVCReceiptPrefixes = []string{
		"com.cisco.secureclient.",
		"com.cisco.pkg.secureclient.",
		"com.cisco.pkg.anyconnect.",
	}
	endpointHealthAVCReceiptMarkers = []string{"avc", "agentic"}
)

// endpointHealthAVCReceiptCandidate reports whether a receipt id matches
// the candidate rule above.
func endpointHealthAVCReceiptCandidate(id string) bool {
	id = strings.ToLower(strings.TrimSpace(id))
	if strings.Contains(id, "defenseclaw") {
		return false
	}
	prefixed := false
	for _, prefix := range endpointHealthAVCReceiptPrefixes {
		prefixed = prefixed || strings.HasPrefix(id, prefix)
	}
	if !prefixed {
		return false
	}
	for _, marker := range endpointHealthAVCReceiptMarkers {
		if strings.Contains(id, marker) {
			return true
		}
	}
	return false
}

// readAVCVersion is the PackageVersion of the AVC package receipt, read
// from the receipt property list without running pkgutil.
func readAVCVersion(ctx context.Context) (string, error) {
	return endpointHealthRead(ctx, endpointHealthSourceTimeout, func(ctx context.Context) (string, error) {
		entries, err := os.ReadDir(endpointHealthReceiptDir)
		if err != nil {
			return "", err
		}
		ids := make([]string, 0, 2)
		for _, entry := range entries {
			name := entry.Name()
			if !entry.Type().IsRegular() || !strings.HasSuffix(name, ".plist") {
				continue
			}
			if id := strings.TrimSuffix(name, ".plist"); endpointHealthAVCReceiptCandidate(id) {
				ids = append(ids, id)
			}
		}
		sort.Strings(ids)
		for _, id := range ids {
			if err := ctx.Err(); err != nil {
				return "", err
			}
			value, err := readEndpointHealthReceiptVersion(filepath.Join(endpointHealthReceiptDir, id+".plist"))
			if err == nil {
				return value, nil
			}
		}
		return "", errors.New("no AVC package receipt with a valid version was found")
	})
}

func readEndpointHealthReceiptVersion(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("receipt is not a regular file")
	}
	file, err := os.Open(path) // #nosec G304 -- a fixed system receipt directory.
	if err != nil {
		return "", err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, endpointHealthPlistMaxBytes+1))
	if err != nil {
		return "", err
	}
	raw, err := plistTopLevelString(data, "PackageVersion")
	if err != nil {
		return "", err
	}
	value, ok := normalizeEndpointHealthVersion(raw)
	if !ok {
		return "", errors.New("receipt PackageVersion is not a valid version")
	}
	return value, nil
}

// readInstalledProductVersion has no installed-version source on macOS;
// the caller keeps the running binary's version.
func readInstalledProductVersion() (string, error) { return "", errEndpointHealthSourceUnavailable }

// readOSVersion is the macOS product version, for example "15.5".
func readOSVersion() string {
	value, err := unix.Sysctl("kern.osproductversion")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(value)
}
