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
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// The guardian swaps the hook program the way Setup's SwapLaunchableFile
// does (GAP-0240, GAP-0656): the old file first gets a second name,
// <destination>.backup.<32 hex>, then one POSIX-semantics rename puts the new
// file at the name agents start. Both steps are plain handle operations on
// purpose. In a file transaction (TxF) Windows refuses to start a program
// image for anyone outside the transaction until it commits
// (ERROR_CANNOT_EXECUTE_FILE_IN_TRANSACTION, 6838) and answered "Access is
// denied" for a few milliseconds around the commit: 6,316 of 7,193 hook
// starts failed while the guardian restored through the transacted
// safefile.ReplaceFileAtomically (GAP-0656 review M1). So this swap never
// joins a transaction, whatever safefile does for other files.

// windowsImageRenameAttempts and windowsImageRenameDelay bound the retries of
// a rename another handle briefly refuses (an antivirus scan, a hook start).
const (
	windowsImageRenameAttempts = 3000
	windowsImageRenameDelay    = time.Millisecond
)

// FILE_RENAME_INFO flags (FileRenameInfoEx).
const (
	windowsFileRenameReplaceIfExists = 0x00000001
	windowsFileRenamePOSIXSemantics  = 0x00000002
)

// errWindowsImageSwapLinkRefused reports that the volume or a filter driver
// refuses the backup hard link the swap needs. Nothing changed; the caller
// replaces the file the older way (GAP-0369).
var errWindowsImageSwapLinkRefused = errors.New("the volume refuses the hard link the one-step swap keeps the old program under")

// windowsImageSwapLinkRefusedCodes are the CreateHardLink errors of a volume
// or a filter driver that does not link files: the same set the lifecycle
// module's Invoke-DefenseClawLaunchableFileSwap falls back on.
var windowsImageSwapLinkRefusedCodes = []windows.Errno{
	windows.ERROR_INVALID_FUNCTION, // 1
	windows.ERROR_NOT_SAME_DEVICE,  // 17
	windows.ERROR_NOT_SUPPORTED,    // 50
	windows.ERROR_TOO_MANY_LINKS,   // 1142
}

// windowsImageSwapRename is the rename step; tests replace it.
var windowsImageSwapRename = renameWindowsProgramImage

// windowsImageSwapLink is the backup-link step; tests replace it.
var windowsImageSwapLink = func(link, existing string) error {
	to, err := winpath.UTF16Ptr(link)
	if err != nil {
		return err
	}
	from, err := winpath.UTF16Ptr(existing)
	if err != nil {
		return err
	}
	return windows.CreateHardLink(to, from, 0)
}

// swapWindowsProgramImage puts temporary at destination in one rename and
// returns the backup name that still holds the old file. The caller removes
// the backup later (deferWindowsImageBackupRemoval): a program that still
// runs the old image keeps it alive, and Windows refuses to delete it then.
// On an error nothing changed: the backup link made for the attempt is
// removed again, and destination is the old file.
func swapWindowsProgramImage(temporary, destination string) (string, error) {
	suffix := make([]byte, 16)
	if _, err := rand.Read(suffix); err != nil {
		return "", err
	}
	backup := destination + ".backup." + hex.EncodeToString(suffix)
	if err := windowsImageSwapLink(backup, destination); err != nil {
		for _, code := range windowsImageSwapLinkRefusedCodes {
			if errors.Is(err, code) {
				return "", fmt.Errorf("%w (%v)", errWindowsImageSwapLinkRefused, err)
			}
		}
		return "", fmt.Errorf("keep the old file as %s: %w", backup, err)
	}
	if err := windowsImageSwapRename(temporary, destination); err != nil {
		_ = os.Remove(backup)
		return "", err
	}
	// The backup name is the old program under a second name for as long as
	// a process runs it. Nothing refers to the name, and a user must not be
	// able to start the old image from it, so it takes an
	// administrators-only access list. A process already running the image,
	// and one that opened it a moment before the rename, are unaffected. A
	// failure does not undo the swap; the guardian logs it once.
	if err := windowsImageBackupRestrict(backup); err != nil {
		windowsImageBackupRestrictFailure.backup, windowsImageBackupRestrictFailure.err = backup, err.Error()
	} else {
		windowsImageBackupRestrictLogged = ""
	}
	return backup, nil
}

// windowsImageBackupSDDL is SYSTEM and Administrators only, protected.
const windowsImageBackupSDDL = "D:P(A;;FA;;;SY)(A;;FA;;;BA)"

// windowsImageBackupRestrict is the access-list step on a backup; tests
// replace it.
var windowsImageBackupRestrict = restrictWindowsImageBackup

func restrictWindowsImageBackup(path string) error {
	descriptor, err := windows.SecurityDescriptorFromString(windowsImageBackupSDDL)
	if err != nil {
		return err
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

// renameWindowsProgramImage renames source over destination with POSIX
// semantics, outside any file transaction, so a program that has the old
// file open (a running hook image, a reader that shares deletion) keeps it
// and the next start finds the new file. A volume that refuses the POSIX
// form gets the classic replacing rename, which Windows refuses while a
// handle has the destination open; busy refusals are retried for about
// three seconds.
func renameWindowsProgramImage(source, destination string) error {
	posixRefused := false
	var err error
	for attempt := 0; attempt < windowsImageRenameAttempts; attempt++ {
		if !posixRefused {
			err = renameWindowsFileByHandle(source, destination, windows.FileRenameInfoEx,
				windowsFileRenameReplaceIfExists|windowsFileRenamePOSIXSemantics)
			if errors.Is(err, windows.ERROR_INVALID_PARAMETER) ||
				errors.Is(err, windows.ERROR_NOT_SUPPORTED) ||
				errors.Is(err, windows.ERROR_INVALID_FUNCTION) {
				posixRefused = true
			}
		}
		if posixRefused {
			// FILE_RENAME_INFO.ReplaceIfExists shares its first byte with Flags.
			err = renameWindowsFileByHandle(source, destination, windows.FileRenameInfo, 1)
		}
		if err == nil {
			return nil
		}
		if !errors.Is(err, windows.ERROR_ACCESS_DENIED) &&
			!errors.Is(err, windows.ERROR_SHARING_VIOLATION) &&
			!errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			break
		}
		time.Sleep(windowsImageRenameDelay)
	}
	if posixRefused {
		return fmt.Errorf("%w (the volume refuses the POSIX-semantics rename; %s is unchanged)", err, destination)
	}
	return err
}

// windowsFileRenameInformation is FILE_RENAME_INFO without its variable
// file name.
type windowsFileRenameInformation struct {
	Flags          uint32
	RootDirectory  windows.Handle
	FileNameLength uint32
	FileName       [1]uint16
}

func renameWindowsFileByHandle(source, destination string, class uint32, flags uint32) error {
	from, err := winpath.UTF16Ptr(source)
	if err != nil {
		return err
	}
	name, err := windows.UTF16FromString(destination)
	if err != nil {
		return err
	}
	handle, err := windows.CreateFile(from, windows.DELETE|windows.SYNCHRONIZE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle)
	// name ends in its terminating zero; FileNameLength excludes it.
	size := unsafe.Offsetof(windowsFileRenameInformation{}.FileName) + uintptr(len(name))*2
	buffer := make([]uint64, (size+7)/8)
	information := (*windowsFileRenameInformation)(unsafe.Pointer(&buffer[0]))
	information.Flags = flags
	information.FileNameLength = uint32((len(name) - 1) * 2)
	copy(unsafe.Slice(&information.FileName[0], len(name)), name)
	return windows.SetFileInformationByHandle(handle, class, (*byte)(unsafe.Pointer(information)), uint32(size))
}

// windowsImageBackupMinAge is how long a backup the guardian's swap made
// stays before the guardian deletes it, at a later check at the earliest.
// Deleting the old file in the instant after the rename gave concurrent
// starts "Access is denied" for up to 12 ms (GAP-0656 review M1); a check is
// windowsHookBinaryCheckInterval apart.
var windowsImageBackupMinAge = time.Second

// windowsImageBackups are the backups this guardian's swaps made and has not
// deleted yet, with the time of each swap.
var windowsImageBackups = struct {
	sync.Mutex
	pending map[string]windowsImageBackup
}{pending: map[string]windowsImageBackup{}}

// windowsImageBackup is one pending backup, keyed by its lower-case path.
type windowsImageBackup struct {
	path string
	made time.Time
}

var windowsImageBackupNow = time.Now

func deferWindowsImageBackupRemoval(backup string) {
	windowsImageBackups.Lock()
	defer windowsImageBackups.Unlock()
	windowsImageBackups.pending[strings.ToLower(backup)] = windowsImageBackup{path: backup, made: windowsImageBackupNow()}
}

// pendingWindowsImageBackups is how many backups the guardian's swaps made
// and has not been able to delete yet.
func pendingWindowsImageBackups() int {
	windowsImageBackups.Lock()
	defer windowsImageBackups.Unlock()
	return len(windowsImageBackups.pending)
}

// windowsImageBackupTooFresh reports a backup the guardian's own swap made
// less than windowsImageBackupMinAge ago.
func windowsImageBackupTooFresh(path string) bool {
	windowsImageBackups.Lock()
	defer windowsImageBackups.Unlock()
	backup, ok := windowsImageBackups.pending[strings.ToLower(path)]
	return ok && windowsImageBackupNow().Sub(backup.made) < windowsImageBackupMinAge
}

// removeDueWindowsImageBackups deletes the backups the guardian's swaps made
// at least windowsImageBackupMinAge ago that no program runs any more, and
// returns them. One a program still runs stays pending for the next check.
func removeDueWindowsImageBackups() []string {
	windowsImageBackups.Lock()
	defer windowsImageBackups.Unlock()
	var removed []string
	now := windowsImageBackupNow()
	for key, backup := range windowsImageBackups.pending {
		if now.Sub(backup.made) < windowsImageBackupMinAge {
			continue
		}
		err := os.Remove(backup.path)
		switch {
		case err == nil:
			removed = append(removed, backup.path)
			delete(windowsImageBackups.pending, key)
		case errors.Is(err, os.ErrNotExist):
			delete(windowsImageBackups.pending, key)
		}
	}
	return removed
}

// forgetWindowsImageBackup drops a backup that was deleted another way.
func forgetWindowsImageBackup(path string) {
	windowsImageBackups.Lock()
	defer windowsImageBackups.Unlock()
	delete(windowsImageBackups.pending, strings.ToLower(path))
}
