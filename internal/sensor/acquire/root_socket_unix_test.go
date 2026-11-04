// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package acquire

import (
	"context"
	"errors"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

type fakeInfo struct {
	mode fs.FileMode
	uid  uint32
}

func (f fakeInfo) Name() string       { return "x" }
func (f fakeInfo) Size() int64        { return 0 }
func (f fakeInfo) Mode() fs.FileMode  { return f.mode }
func (f fakeInfo) ModTime() time.Time { return time.Time{} }
func (f fakeInfo) IsDir() bool        { return f.mode.IsDir() }
func (f fakeInfo) Sys() any           { return &syscall.Stat_t{Uid: f.uid} }

// The Cowork VM layout: /run/defenseclaw-cowork-sensor/sensor-helper.sock,
// socket root:<gateway group> 0660 in a root:<gateway group> 0750 folder.
func coworkTree() map[string]fakeInfo {
	return map[string]fakeInfo{
		"/":                                     {fs.ModeDir | 0o755, 0},
		"/run":                                  {fs.ModeDir | 0o755, 0},
		"/run/defenseclaw-cowork-sensor":        {fs.ModeDir | 0o750, 0},
		"/run/defenseclaw-cowork-sensor/s.sock": {fs.ModeSocket | 0o660, 0},
	}
}

func lstatOf(tree map[string]fakeInfo) func(string) (fs.FileInfo, error) {
	return func(path string) (fs.FileInfo, error) {
		info, ok := tree[path]
		if !ok {
			return nil, fs.ErrNotExist
		}
		return info, nil
	}
}

func TestCheckRootSocketTrustsOnlyARootOwnedTree(t *testing.T) {
	const socket = "/run/defenseclaw-cowork-sensor/s.sock"
	if err := checkRootSocket(socket, lstatOf(coworkTree())); err != nil {
		t.Fatalf("the root-owned Cowork helper socket was refused: %v", err)
	}
	cases := map[string]func(map[string]fakeInfo){
		"socket owned by another account": func(t map[string]fakeInfo) { t[socket] = fakeInfo{fs.ModeSocket | 0o660, 997} },
		"socket writable by others":       func(t map[string]fakeInfo) { t[socket] = fakeInfo{fs.ModeSocket | 0o666, 0} },
		"not a socket":                    func(t map[string]fakeInfo) { t[socket] = fakeInfo{0o600, 0} },
		"socket is a symbolic link":       func(t map[string]fakeInfo) { t[socket] = fakeInfo{fs.ModeSymlink | 0o777, 0} },
		"folder writable by the group":    func(t map[string]fakeInfo) { t["/run/defenseclaw-cowork-sensor"] = fakeInfo{fs.ModeDir | 0o770, 0} },
		"folder writable by others":       func(t map[string]fakeInfo) { t["/run"] = fakeInfo{fs.ModeDir | 0o1777, 0} },
		"folder owned by another account": func(t map[string]fakeInfo) { t["/run/defenseclaw-cowork-sensor"] = fakeInfo{fs.ModeDir | 0o750, 1001} },
		"folder is a symbolic link":       func(t map[string]fakeInfo) { t["/run/defenseclaw-cowork-sensor"] = fakeInfo{fs.ModeSymlink | 0o777, 0} },
		"socket missing":                  func(t map[string]fakeInfo) { delete(t, socket) },
	}
	for name, mutate := range cases {
		tree := coworkTree()
		mutate(tree)
		if err := checkRootSocket(socket, lstatOf(tree)); err == nil {
			t.Errorf("%s: trusted", name)
		}
	}
	if err := checkRootSocket("run/s.sock", lstatOf(coworkTree())); err == nil {
		t.Error("a relative path was trusted")
	}
	if err := checkRootSocket("/run/../run/defenseclaw-cowork-sensor/s.sock", lstatOf(coworkTree())); err == nil {
		t.Error("an unclean path was trusted")
	}
}

// A socket this (non-root) test process serves stands in for an account that
// binds a socket where the gateway's environment points: the path check and
// the serving-uid check both refuse it.
func TestRootHelperRefusesASocketANonRootProcessServes(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("needs a non-root test process to serve the socket")
	}
	dir, err := os.MkdirTemp("", "dcrs")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "s.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	if err := CheckRootSocket(path); err == nil {
		t.Fatal("a socket in a folder this account owns was trusted")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := ProbeRootHelper(ctx, path); !errors.Is(err, ErrHelperNotRoot) {
		t.Fatalf("probe of a non-root server = %v, want ErrHelperNotRoot", err)
	}
	if _, _, err := NewRootHelper(path).Processes(ctx); !errors.Is(err, ErrHelperNotRoot) {
		t.Fatalf("Processes through a non-root server = %v, want ErrHelperNotRoot", err)
	}
	if err := ProbeRootHelper(ctx, filepath.Join(dir, "absent.sock")); err != nil {
		t.Fatalf("a helper not listening yet = %v, want nil (each connect checks again)", err)
	}
}

// cowork-1-0-8 GAP-0049: only a socket missing from folders only root can
// write is worth waiting for.
func TestRootSocketAwaitableOnlyBelowRootOnlyFolders(t *testing.T) {
	dir := func(uid uint32, perm fs.FileMode) fs.FileInfo { return fakeInfo{mode: fs.ModeDir | perm, uid: uid} }
	for _, tc := range []struct {
		name    string
		entries map[string]fs.FileInfo
		want    bool
	}{
		{"absent socket, runtime folder missing below root-only /run", map[string]fs.FileInfo{"/run": dir(0, 0o755), "/": dir(0, 0o755)}, true},
		{"absent socket in a root-only runtime folder", map[string]fs.FileInfo{"/run/h": dir(0, 0o750), "/run": dir(0, 0o755), "/": dir(0, 0o755)}, true},
		{"absent socket in a user folder", map[string]fs.FileInfo{"/run/h": dir(1000, 0o700), "/run": dir(0, 0o755), "/": dir(0, 0o755)}, false},
		{"absent socket below a world-writable folder", map[string]fs.FileInfo{"/run": dir(0, 0o777), "/": dir(0, 0o755)}, false},
		{"socket present", map[string]fs.FileInfo{"/run/h/s.sock": fakeInfo{mode: fs.ModeSocket | 0o660}, "/run/h": dir(0, 0o750), "/run": dir(0, 0o755), "/": dir(0, 0o755)}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lstat := func(path string) (fs.FileInfo, error) {
				if info, ok := tc.entries[path]; ok {
					return info, nil
				}
				return nil, fs.ErrNotExist
			}
			if got := rootSocketAwaitable("/run/h/s.sock", lstat); got != tc.want {
				t.Fatalf("awaitable = %t, want %t", got, tc.want)
			}
		})
	}
}
