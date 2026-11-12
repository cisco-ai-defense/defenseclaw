// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package testenv

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// IsolateUserRoots is the TestMain default for a package whose tests run a
// connector Setup. A connector can resolve its config folder from a per-user
// root that is not the home: Devin on Windows reads %APPDATA%. A test that
// moves the home with t.Setenv("USERPROFILE", ...) alone leaves that root on
// the developers real profile, so the test wrote the developers own Devin
// config.json, and the foreign-hook guard tests then read it back and failed
// (GAP-0887). SetHome moves every root for one test; this moves them for the
// whole run, so a test that forgot lands in a folder of the run that is
// removed afterwards.
//
// The returned function ends the isolation: it restores the environment,
// removes the run folder, and reports every change to the real folders the
// run was meant to leave alone. Call it after m.Run and fail the run on a
// non-nil error. Off Windows it does nothing.
func IsolateUserRoots() (func() error, error) {
	return isolateUserRoots(watchedUserRoots(), redirectedUserRoots)
}

func isolateUserRoots(watch []string, redirect func(runDir string) map[string]string) (func() error, error) {
	before := takeSnapshot(watch)
	runDir, err := os.MkdirTemp("", "defenseclaw-user-roots-")
	if err != nil {
		return nil, fmt.Errorf("create the run folder for the per-user roots: %w", err)
	}
	previous := map[string]*string{}
	restore := func() {
		for name, value := range previous {
			if value == nil {
				_ = os.Unsetenv(name)
			} else {
				_ = os.Setenv(name, *value)
			}
		}
	}
	for name, value := range redirect(runDir) {
		if old, ok := os.LookupEnv(name); ok {
			previous[name] = &old
		} else {
			previous[name] = nil
		}
		if err := os.MkdirAll(value, 0o700); err != nil {
			restore()
			_ = os.RemoveAll(runDir)
			return nil, fmt.Errorf("create the run folder %s: %w", value, err)
		}
		if err := os.Setenv(name, value); err != nil {
			restore()
			_ = os.RemoveAll(runDir)
			return nil, fmt.Errorf("set %s: %w", name, err)
		}
	}
	return func() error {
		restore()
		_ = os.RemoveAll(runDir)
		changes := before.changes(takeSnapshot(watch))
		if len(changes) == 0 {
			return nil
		}
		return errors.New("the tests changed the real per-user folders; a test must move every per-user root (testenv.SetHome) or use a temp layout:\n  " +
			strings.Join(changes, "\n  "))
	}, nil
}

// snapshot maps every file and folder below the watched folders to its size
// and modification time.
type snapshot map[string]string

func takeSnapshot(roots []string) snapshot {
	state := snapshot{}
	for _, root := range roots {
		_ = filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			info, err := entry.Info()
			if err != nil {
				return nil
			}
			if entry.IsDir() {
				state[path] = "dir"
				return nil
			}
			state[path] = fmt.Sprintf("%d:%d", info.Size(), info.ModTime().UnixNano())
			return nil
		})
	}
	return state
}

// changes names what the later snapshot added, changed or removed.
func (s snapshot) changes(after snapshot) []string {
	var out []string
	for path, state := range after {
		switch old, ok := s[path]; {
		case !ok:
			out = append(out, "added "+path)
		case old != state:
			out = append(out, "changed "+path)
		}
	}
	for path := range s {
		if _, ok := after[path]; !ok {
			out = append(out, "removed "+path)
		}
	}
	sort.Strings(out)
	return out
}
