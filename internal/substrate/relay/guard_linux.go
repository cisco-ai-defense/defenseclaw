// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package relay

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// guardEvery is how often the guarded folders are also looked at (a restore
// from a snapshot, which no watch event announces).
var guardEvery = time.Second

// inotifyAddWatch sets one watch (a test seam: a watch that cannot be set).
var inotifyAddWatch = unix.InotifyAddWatch

type dirID struct{ dev, ino uint64 }

func lstatDirOf(p string) (dirID, error) {
	var st unix.Stat_t
	if err := unix.Lstat(p, &st); err != nil {
		return dirID{}, fmt.Errorf("%s: %w", p, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return dirID{}, fmt.Errorf("%s is not a folder", p)
	}
	return dirID{uint64(st.Dev), st.Ino}, nil
}

// Guard watch masks: on the parent, a guarded name that is moved away,
// renamed onto or deleted; on the folder itself, a move (also one half of a
// RENAME_EXCHANGE) or its removal.
const (
	guardParentMask = unix.IN_MOVED_FROM | unix.IN_MOVED_TO | unix.IN_DELETE
	guardSelfMask   = unix.IN_MOVE_SELF | unix.IN_DELETE_SELF
)

// watchGuarded watches folders below the agent's HOME that hold DefenseClaw's
// root-owned hook registration (Antigravity's ~/.gemini, GAP-0120). The agent
// owns HOME, so it can rename such a folder away and make its own in its
// place. The relay trips on the watch event itself (substrate-1 GAP-0356): a
// guarded name moved, renamed onto or deleted in its parent, the folder moved
// or removed, or an event queue overflow. A look at the folders' identity
// afterwards would miss a swap that is undone before it (RENAME_EXCHANGE
// there and back). It also compares the identity every guardEvery. broken is
// called once.
//
// The guard fails closed (GAP-0369): a folder that is not there to watch,
// or a watch that cannot be set (inotify limits, a filesystem without
// inotify), is an error, so the relay refuses the agent; the error is a
// *guardDegraded for a watch. A watch that ends while the agent runs (a read
// error, a watch the kernel dropped) is a trip whose reason starts with
// guardWatchEnded.
func watchGuarded(ctx context.Context, dirs []string, broken func(reason string)) error {
	return watchGuardedAs(ctx, dirs, broken, nil)
}

// watchGuardedAs is watchGuarded looking at the folders with cred as the
// file-system identity (a separated relay: the agent's user, GAP-0458). A
// root relay that keeps only SETUID, SETGID and KILL is not exempt from
// file modes, and the guarded folders lie in the agent's HOME, whose mode
// the base image picks (0700 is common).
func watchGuardedAs(ctx context.Context, dirs []string, broken func(reason string), cred agentCred) error {
	if len(dirs) == 0 {
		return nil
	}
	lstatDir := func(p string) (id dirID, err error) {
		withFSCred(cred, func() { id, err = lstatDirOf(p) })
		return id, err
	}
	addWatch := func(fd int, p string, mask uint32) (w int, err error) {
		withFSCred(cred, func() { w, err = inotifyAddWatch(fd, p, mask) })
		return w, err
	}
	ids := map[string]dirID{}
	for _, d := range dirs {
		d = filepath.Clean(d)
		id, err := lstatDir(d)
		if err != nil {
			return err
		}
		ids[d] = id
	}
	// Non-blocking, so the reader is pollable and closing the file ends it.
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		return &guardDegraded{err: fmt.Errorf("inotify: %w", err)}
	}
	// parents: watch descriptor -> guarded base names in that folder;
	// selves: watch descriptor -> guarded folder.
	parents, selves := map[int32]map[string]string{}, map[int32]string{}
	for d := range ids {
		pw, err := addWatch(fd, filepath.Dir(d), guardParentMask)
		if err != nil {
			unix.Close(fd)
			return &guardDegraded{err: fmt.Errorf("watch %s: %w", filepath.Dir(d), err)}
		}
		sw, err := addWatch(fd, d, guardSelfMask)
		if err != nil {
			unix.Close(fd)
			return &guardDegraded{err: fmt.Errorf("watch %s: %w", d, err)}
		}
		if parents[int32(pw)] == nil {
			parents[int32(pw)] = map[string]string{}
		}
		parents[int32(pw)][filepath.Base(d)] = d
		selves[int32(sw)] = d
	}
	var once sync.Once
	tripped := make(chan struct{})
	stop := func(reason string) {
		once.Do(func() {
			close(tripped)
			broken(reason)
		})
	}
	// The watches are set: a change between the identity check above and
	// here is caught by comparing once more.
	for d, want := range ids {
		if got, err := lstatDir(d); err != nil || got != want {
			unix.Close(fd)
			stop(d + " was moved, replaced or removed")
			return nil
		}
	}
	notify := os.NewFile(uintptr(fd), "inotify")
	go func() {
		select {
		case <-ctx.Done():
		case <-tripped:
		}
		notify.Close()
	}()
	go readGuardEvents(ctx, notify, parents, selves, stop)
	go func() {
		t := time.NewTicker(guardEvery)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tripped:
				return
			case <-t.C:
			}
			for d, want := range ids {
				if got, err := lstatDir(d); err != nil || got != want {
					stop(d + " was moved, replaced or removed")
					return
				}
			}
		}
	}()
	return nil
}

// readGuardEvents trips on the first event that concerns a guarded folder,
// and when the watch ends before ctx (GAP-0369).
func readGuardEvents(ctx context.Context, f *os.File, parents map[int32]map[string]string, selves map[int32]string, stop func(string)) {
	buf := make([]byte, 64<<10)
	for {
		n, err := f.Read(buf)
		if err != nil {
			if ctx.Err() == nil {
				stop(guardWatchEnded + " (" + err.Error() + "), so a move of the hook folder could go unseen")
			}
			return
		}
		for off := 0; off+unix.SizeofInotifyEvent <= n; {
			ev := (*unix.InotifyEvent)(unsafe.Pointer(&buf[off]))
			name := ""
			if ev.Len > 0 {
				end := off + unix.SizeofInotifyEvent + int(ev.Len)
				if end > n {
					break
				}
				raw := buf[off+unix.SizeofInotifyEvent : end]
				for i, c := range raw {
					if c == 0 {
						raw = raw[:i]
						break
					}
				}
				name = string(raw)
			}
			off += unix.SizeofInotifyEvent + int(ev.Len)
			switch {
			case ev.Mask&unix.IN_Q_OVERFLOW != 0:
				// Events were lost: one of them may have been the move.
				stop("the guard's event queue overflowed, so a move of the hook folder may have been missed")
				return
			case selves[ev.Wd] != "" && ev.Mask&(guardSelfMask|unix.IN_IGNORED) != 0:
				stop(selves[ev.Wd] + " was moved, replaced or removed")
				return
			case parents[ev.Wd] != nil && parents[ev.Wd][name] != "":
				stop(parents[ev.Wd][name] + " was moved, replaced or removed")
				return
			case parents[ev.Wd] != nil && ev.Mask&unix.IN_IGNORED != 0:
				// The kernel dropped the watch on the parent (removed or
				// unmounted): later moves in it would go unseen.
				stop(guardWatchEnded + " (the watch on the parent folder was dropped), so a move of the hook folder could go unseen")
				return
			}
		}
	}
}
