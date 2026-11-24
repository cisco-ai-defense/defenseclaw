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
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/sys/windows"
)

// GAP-0011: the hook path re-ran ValidateTrustedMachineRoot, uncached,
// several times for each element of every trust walk (the hook token
// location check, the Secure Client host guard and the advisory-ancestor
// scope each resolve Program Files, Program Files (x86) and ProgramData).
// At 35 hook calls per second on dc-win2 309 of 447 gateway goroutines and
// 83% of its CPU sat in it, and the per-user gateway fell off a cliff.
//
// A successful validation is now kept for one exact root value, and only
// while nothing it judged can have changed:
//   - every strict ancestor of the root (the folders whose entries are the
//     root and its parents) has a change notification open from before the
//     validation started, for a rename, a new or removed folder, an
//     attribute change (a reparse point) or an access-list change. A
//     signaled or failed notification drops the entry, and the next call
//     validates in full;
//   - the entry is at most trustedMachineRootCacheMaxAge old, which bounds a
//     change no notification reports (a volume mounted at a different
//     letter);
//   - the registry value is still read by every caller, so a changed
//     registration is a different key and misses.
//
// A failed validation is never kept, and a root whose notifications cannot
// be opened is never kept: the cache only ever skips work it can prove is
// unchanged, and otherwise fails closed to the full check.
const (
	trustedMachineRootCacheMaxAge     = 2 * time.Second
	trustedMachineRootCacheMaxEntries = 16
	trustedMachineRootChangeFilter    = windows.FILE_NOTIFY_CHANGE_DIR_NAME |
		windows.FILE_NOTIFY_CHANGE_ATTRIBUTES |
		windows.FILE_NOTIFY_CHANGE_SECURITY
)

type trustedMachineRootEntry struct {
	clean     string
	validated time.Time
	watches   []windows.Handle
}

var trustedMachineRootCache = struct {
	sync.Mutex
	entries map[string]*trustedMachineRootEntry
}{entries: map[string]*trustedMachineRootEntry{}}

// Seams for tests.
var (
	trustedMachineRootNow              = time.Now
	trustedMachineRootValidateUncached = validateTrustedMachineRootUncached
)

// ValidateTrustedMachineRoot applies the fail-closed syntax, mounted-volume,
// existence, and reparse-chain contract used for protected machine roots,
// served from a change-notified cache for an unchanged root (GAP-0011).
func ValidateTrustedMachineRoot(value, label string) (string, error) {
	if clean, ok := cachedTrustedMachineRoot(value); ok {
		return clean, nil
	}
	// The notifications are open before the validation reads anything, so a
	// change during it signals them and the entry is dropped on its first use.
	watches := openTrustedMachineRootWatches(value)
	clean, err := trustedMachineRootValidateUncached(value, label)
	if err != nil || watches == nil {
		closeTrustedMachineRootWatches(watches)
		forgetTrustedMachineRoot(value)
		return clean, err
	}
	rememberTrustedMachineRoot(value, &trustedMachineRootEntry{
		clean:     clean,
		validated: trustedMachineRootNow(),
		watches:   watches,
	})
	return clean, nil
}

func cachedTrustedMachineRoot(value string) (string, bool) {
	trustedMachineRootCache.Lock()
	defer trustedMachineRootCache.Unlock()
	entry := trustedMachineRootCache.entries[value]
	if entry == nil {
		return "", false
	}
	age := trustedMachineRootNow().Sub(entry.validated)
	if age < 0 || age >= trustedMachineRootCacheMaxAge || !trustedMachineRootWatchesQuiet(entry.watches) {
		delete(trustedMachineRootCache.entries, value)
		closeTrustedMachineRootWatches(entry.watches)
		return "", false
	}
	return entry.clean, true
}

func rememberTrustedMachineRoot(value string, entry *trustedMachineRootEntry) {
	trustedMachineRootCache.Lock()
	defer trustedMachineRootCache.Unlock()
	if previous := trustedMachineRootCache.entries[value]; previous != nil {
		closeTrustedMachineRootWatches(previous.watches)
	} else if len(trustedMachineRootCache.entries) >= trustedMachineRootCacheMaxEntries {
		closeTrustedMachineRootWatches(entry.watches)
		return
	}
	trustedMachineRootCache.entries[value] = entry
}

func forgetTrustedMachineRoot(value string) {
	trustedMachineRootCache.Lock()
	defer trustedMachineRootCache.Unlock()
	if entry := trustedMachineRootCache.entries[value]; entry != nil {
		delete(trustedMachineRootCache.entries, value)
		closeTrustedMachineRootWatches(entry.watches)
	}
}

// openTrustedMachineRootWatches opens a change notification on every strict
// ancestor of value, or returns nil (do not cache) when value is not a clean
// absolute path or any notification cannot be opened.
func openTrustedMachineRootWatches(value string) []windows.Handle {
	if value == "" || filepath.Clean(value) != value || !isLocalDriveLetterSyntax(value) {
		return nil
	}
	var watches []windows.Handle
	for current := value; ; {
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		extended, err := Extended(parent)
		if err != nil {
			closeTrustedMachineRootWatches(watches)
			return nil
		}
		handle, err := windows.FindFirstChangeNotification(extended, false, trustedMachineRootChangeFilter)
		if err != nil || handle == windows.InvalidHandle {
			closeTrustedMachineRootWatches(watches)
			return nil
		}
		watches = append(watches, handle)
		current = parent
	}
	if len(watches) == 0 {
		return nil
	}
	return watches
}

// trustedMachineRootWatchesQuiet reports whether no notification has been
// signaled. Any other wait result (an error, an abandoned handle) is a
// change.
func trustedMachineRootWatchesQuiet(watches []windows.Handle) bool {
	if len(watches) == 0 {
		return false
	}
	for _, handle := range watches {
		event, err := windows.WaitForSingleObject(handle, 0)
		if err != nil || event != uint32(windows.WAIT_TIMEOUT) {
			return false
		}
	}
	return true
}

func closeTrustedMachineRootWatches(watches []windows.Handle) {
	for _, handle := range watches {
		_ = windows.FindCloseChangeNotification(handle)
	}
}
