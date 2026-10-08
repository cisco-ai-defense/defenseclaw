// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// macOSTCCHomeFolders are the home folders macOS privacy protection (TCC)
// guards with a prompt for a process in a user's GUI session: Desktop,
// Documents and Downloads, the Photos, Music and Movies libraries, iCloud
// Drive, other apps' data in Containers and Group Containers, and Contacts.
// A scan that opens one makes macOS ask the user whether
// "defenseclaw-gateway" may access it, again after every Don't Allow, so a
// scan without Full Disk Access never enters them. EPERM from the folders
// that deny without a prompt is skipped separately (macOSPrivacyDenied).
var macOSTCCHomeFolders = []string{
	"Desktop", "Documents", "Downloads", "Movies", "Music", "Pictures",
	"Library/Mobile Documents",
	"Library/Containers", "Library/Group Containers",
	"Library/Application Support/AddressBook",
}

// macOSTCCProtectedPath reports whether path is inside one of
// macOSTCCHomeFolders of the given homes. APFS is case-insensitive by
// default, so the match ignores case.
func macOSTCCProtectedPath(path string, homes []string) bool {
	path = filepath.Clean(path)
	for _, home := range homes {
		rel, err := filepath.Rel(filepath.Clean(home), path)
		if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			continue
		}
		rel = strings.ToLower(filepath.ToSlash(rel))
		for _, folder := range macOSTCCHomeFolders {
			folder = strings.ToLower(folder)
			if rel == folder || strings.HasPrefix(rel, folder+"/") {
				return true
			}
		}
	}
	return false
}

// discoveryGOOS is the system the scans run on; tests replace it.
var discoveryGOOS = runtime.GOOS

// macOSFullDiskAccess reports whether this process holds Full Disk Access,
// which a PPPC profile grants to the gateway binary. Tests replace it.
var macOSFullDiskAccess = cachedMacOSFullDiskAccess

// fullDiskAccessTTL bounds how long a probe answer is reused, so a PPPC
// profile installed while the gateway runs takes effect without a restart.
const fullDiskAccessTTL = 10 * time.Minute

var fullDiskAccessCache struct {
	sync.Mutex
	checked time.Time
	granted bool
}

func cachedMacOSFullDiskAccess() bool {
	cache := &fullDiskAccessCache
	cache.Lock()
	defer cache.Unlock()
	if cache.checked.IsZero() || time.Since(cache.checked) > fullDiskAccessTTL {
		cache.granted, cache.checked = probeMacOSFullDiskAccess(), time.Now()
	}
	return cache.granted
}

// probeMacOSFullDiskAccess opens the system TCC database, which macOS lets
// only a process with Full Disk Access read. That service never prompts: a
// process without it gets EPERM, and the probe runs in the scanning process
// itself because the grant is per binary, not per user.
func probeMacOSFullDiskAccess() bool {
	file, err := os.Open("/Library/Application Support/com.apple.TCC/TCC.db")
	if err != nil {
		return false
	}
	_ = file.Close()
	return true
}

// macOSTCCSkipped reports a path the scan must not open: on macOS, a folder
// that would raise a privacy prompt, unless Full Disk Access is granted. The
// probe runs only when a scan reaches such a folder.
func (s *ContinuousDiscoveryService) macOSTCCSkipped(path string) bool {
	if s == nil || s.opts.SecureClient || discoveryGOOS != "darwin" ||
		!macOSTCCProtectedPath(path, s.homesToScan()) || macOSFullDiskAccess() {
		return false
	}
	s.tccSkipped = true
	return true
}
