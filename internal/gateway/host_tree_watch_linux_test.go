// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package gateway

import (
	"errors"
	"io/fs"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

// watchHostTreeOpens reports every open(2) of a file or directory under root
// (reads, directory listings, git, subprocess scanners) from the moment it
// is called until the returned function runs. Stat-only access raises no
// inotify event; the copy-mode test covers that with its unreadable pass.
func watchHostTreeOpens(t *testing.T, root string) func() []string {
	t.Helper()
	fd, err := unix.InotifyInit1(unix.IN_NONBLOCK | unix.IN_CLOEXEC)
	if err != nil {
		t.Skipf("inotify unavailable: %v", err)
	}
	dirs := map[int32]string{}
	walkErr := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() {
			return nil
		}
		wd, err := unix.InotifyAddWatch(fd, path, unix.IN_OPEN|unix.IN_ACCESS|unix.IN_DONT_FOLLOW)
		if err != nil {
			return err
		}
		dirs[int32(wd)] = path
		return nil
	})
	if walkErr != nil {
		_ = unix.Close(fd)
		t.Fatalf("watch %s: %v", root, walkErr)
	}
	// Drain anything the walk itself raised.
	drain := func() []string {
		var opened []string
		buf := make([]byte, 64<<10)
		for {
			n, err := unix.Read(fd, buf)
			if err != nil || n <= 0 {
				if err != nil && !errors.Is(err, unix.EAGAIN) {
					t.Errorf("read inotify events: %v", err)
				}
				return opened
			}
			for offset := 0; offset+unix.SizeofInotifyEvent <= n; {
				event := (*unix.InotifyEvent)(unsafe.Pointer(&buf[offset]))
				name := ""
				if event.Len > 0 {
					raw := buf[offset+unix.SizeofInotifyEvent : offset+unix.SizeofInotifyEvent+int(event.Len)]
					for i, b := range raw {
						if b == 0 {
							raw = raw[:i]
							break
						}
					}
					name = string(raw)
				}
				opened = append(opened, filepath.Join(dirs[event.Wd], name))
				offset += unix.SizeofInotifyEvent + int(event.Len)
			}
		}
	}
	drain()
	return func() []string {
		defer unix.Close(fd)
		return drain()
	}
}
