// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package pathidentity

import (
	"errors"
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

// ErrLinked is the error of HoldUnlinked for a path whose last component is
// a link (a symbolic link, a junction or another name surrogate), or on
// Windows one with a link on the way.
var ErrLinked = errors.New("pathidentity: the last component of the path is a link")

// ErrUnpinned is the error of HoldUnlinked on Windows for a component it
// cannot open at all (the paging file and the like). What a read of it
// would show is unknown (rel-1-0-10:GAP-1264).
var ErrUnpinned = errors.New("pathidentity: the component cannot be held against a rename")

// HoldUnlinked holds the last component of path, which a check has read as
// no link, for a read of the path that follows it: a component that is a
// link now is refused (ErrLinked) before anything opens it, so a read never
// follows a link the check did not see. still, called once after the read,
// releases the hold and reports whether the component stayed no link for
// the whole read; a read for which it reports false is to be discarded.
//
// On Windows the whole path is opened once, following no link on the way
// and not the last component, for data access without delete sharing:
// while it is held no one can rename or delete the component or any folder
// above it, so no link can take the place of any of them, and a folder on
// the way that is a link now is refused (ErrLinked, rel-1-0-10:GAP-1263). A
// component that cannot be held so (another handle denies read sharing or
// has delete access, or the account may neither read nor enter it) is held
// for its attributes, which still pins the folders above it, and still()
// reports false unless its name then opens the same file with no link on
// the way. One that cannot be opened at all is ErrUnpinned: it is not read
// (rel-1-0-10:GAP-1264). On other platforms it is read with lstat before and
// after the read.
//
// A component that does not exist, or a name that cannot name a file, is
// that error.
func HoldUnlinked(path string) (still func() bool, err error) {
	return holdUnlinked(path)
}
