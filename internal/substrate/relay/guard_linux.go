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

	"golang.org/x/sys/unix"
)

// guardEvery is how often the guarded folders are looked at besides the
// inotify events (a missed event, a restore from a snapshot).
var guardEvery = time.Second

type dirID struct{ dev, ino uint64 }

func lstatDir(p string) (dirID, error) {
	var st unix.Stat_t
	if err := unix.Lstat(p, &st); err != nil {
		return dirID{}, fmt.Errorf("%s: %w", p, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return dirID{}, fmt.Errorf("%s is not a folder", p)
	}
	return dirID{uint64(st.Dev), st.Ino}, nil
}

// watchGuarded watches folders below the agent's HOME that hold DefenseClaw's
// root-owned hook registration (Antigravity's ~/.gemini, GAP-0120). The agent
// owns HOME, so it can rename such a folder away and make its own in its
// place; the relay, which the agent can neither stop nor trace, sees the
// folder's identity change (inotify on its parent, and a look every
// guardEvery) and calls broken once. It fails when a folder is not there to
// watch.
func watchGuarded(ctx context.Context, dirs []string, broken func(reason string)) error {
	if len(dirs) == 0 {
		return nil
	}
	ids := map[string]dirID{}
	for _, d := range dirs {
		id, err := lstatDir(d)
		if err != nil {
			return err
		}
		ids[d] = id
	}
	var once sync.Once
	check := func() bool {
		for d, want := range ids {
			if got, err := lstatDir(d); err != nil || got != want {
				once.Do(func() { broken(d + " was moved, replaced or removed") })
				return true
			}
		}
		return false
	}
	events := make(chan struct{}, 1)
	var notify *os.File
	if fd, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK); err == nil {
		notify = os.NewFile(uintptr(fd), "inotify")
		seen := map[string]bool{}
		for d := range ids {
			if p := filepath.Dir(d); !seen[p] {
				seen[p] = true
				_, _ = unix.InotifyAddWatch(fd, p, unix.IN_MOVED_FROM|unix.IN_MOVED_TO|unix.IN_DELETE|unix.IN_CREATE)
			}
			_, _ = unix.InotifyAddWatch(fd, d, unix.IN_MOVE_SELF|unix.IN_DELETE_SELF)
		}
		go func() {
			buf := make([]byte, 16<<10)
			for {
				if _, err := notify.Read(buf); err != nil {
					return
				}
				select {
				case events <- struct{}{}:
				default:
				}
			}
		}()
	}
	go func() {
		t := time.NewTicker(guardEvery)
		defer t.Stop()
		if notify != nil {
			defer notify.Close()
		}
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			case <-events:
			}
			if check() {
				return
			}
		}
	}()
	return nil
}
