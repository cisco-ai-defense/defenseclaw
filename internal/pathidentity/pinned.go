// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package pathidentity

import (
	"os"
	"sync/atomic"
)

// LstatPinned is os.Lstat with the file identity already loaded.
//
// A check-then-use guard takes a FileInfo by path, checks the file, opens
// the path and requires os.SameFile(info, opened). On Windows os.Lstat and
// os.Stat return a FileInfo that reads its volume serial and file index
// lazily, by path, at the first os.SameFile. The comparison then reads the
// identity of whatever file holds the path after the open, compares the
// opened file with itself and accepts a file swapped in after the check.
// LstatPinned (and StatPinned) read the attributes and the identity from
// one handle at once, so the comparison binds the file that was checked.
// On other platforms they are os.Lstat and os.Stat, which read the device
// and inode at once.
//
// Use it for the FileInfo a guard takes before its checks. A FileInfo from
// (*os.File).Stat is already bound to its handle, and one taken after the
// open to prove that the path still names the opened file is right as it is.
func LstatPinned(path string) (os.FileInfo, error) {
	info, err := lstatPinned(path)
	if err == nil {
		runPinnedStatHook(path)
	}
	return info, err
}

// StatPinned is os.Stat with the file identity already loaded; see
// LstatPinned.
func StatPinned(path string) (os.FileInfo, error) {
	info, err := statPinned(path)
	if err == nil {
		runPinnedStatHook(path)
	}
	return info, err
}

var pinnedStatHook atomic.Pointer[func(string)]

func runPinnedStatHook(path string) {
	if hook := pinnedStatHook.Load(); hook != nil {
		(*hook)(path)
	}
}

// SetPinnedStatHookForTest makes fn run after each successful LstatPinned or
// StatPinned, once the identity is loaded and before the caller sees it.
// Tests use it to swap a file at the check/use instant without timing. It
// returns a function that removes the hook.
func SetPinnedStatHookForTest(fn func(path string)) (restore func()) {
	pinnedStatHook.Store(&fn)
	return func() { pinnedStatHook.Store(nil) }
}
