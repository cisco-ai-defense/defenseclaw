// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// GAP-0091: a macOS purge removes /opt/cisco and /Library/Logs/Cisco only
// when the deployment recorded creating them. Empty folders that existed
// before the install stay; the ones the lifecycle created go.
func TestDarwinPurgeRemovesOnlyTheSharedParentsItCreated(t *testing.T) {
	for _, existed := range []bool{true, false} {
		name := map[bool]string{true: "existed before", false: "created by the install"}[existed]
		t.Run(name, func(t *testing.T) {
			h := newTestHost(t, "darwin")
			parents := []string{"/opt", "/opt/cisco", "/Library/Logs/Cisco"}
			if existed {
				for _, dir := range parents {
					if err := os.MkdirAll(h.env.P(dir), 0o755); err != nil {
						t.Fatal(err)
					}
				}
			}
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
			requireOK(t, h.run(Options{Action: ActionUninstall, Purge: true}))
			for _, dir := range parents {
				if exists(h.env.P(dir)) != existed {
					t.Errorf("after the purge %s present=%t, want %t", dir, exists(h.env.P(dir)), existed)
				}
			}
		})
	}
}

// The package preinstall and the first lock folder list the shared parents
// that did not exist; the lifecycle reads only a trusted list on macOS and
// only the allowed parents.
func TestCreatedParentDirsReadsOnlyTheTrustedAllowedList(t *testing.T) {
	write := func(t *testing.T, h *testHost, body string) string {
		t.Helper()
		path := h.env.P(h.env.createdParentDirsPath())
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	h := newTestHost(t, "darwin")
	write(t, h, "/opt\n/opt/cisco\n/etc\n/opt/cisco/../etc\n/usr/local/bin\n/opt\n")
	if got := h.env.createdParentDirs(); !slices.Equal(got, []string{"/opt", "/opt/cisco", "/usr/local/bin"}) {
		t.Fatalf("createdParentDirs = %v, want the allowed parents once", got)
	}
	h.env.Trust = func(string, TrustKind) error { return errors.New("owned by uid 501") }
	if got := h.env.createdParentDirs(); got != nil {
		t.Fatalf("an untrusted list was read: %v", got)
	}
	linux := newTestHost(t, "linux")
	write(t, linux, "/opt\n")
	if got := linux.env.createdParentDirs(); got != nil {
		t.Fatalf("Linux read a macOS package list: %v", got)
	}
	link := newTestHost(t, "darwin")
	target := write(t, link, "/opt\n")
	moved := target + ".real"
	if err := os.Rename(target, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(moved, target); err != nil {
		t.Fatal(err)
	}
	if got := link.env.createdParentDirs(); got != nil {
		t.Fatalf("a symlinked list was read: %v", got)
	}
}

// The launcher's folders are recorded only when the lifecycle creates them,
// so an uninstall keeps a /usr/local/bin that existed before and removes one
// it created once empty.
func TestLauncherParentDirsAreRecordedSharedParents(t *testing.T) {
	h := newTestHost(t, "darwin")
	got := h.env.launcherParentDirs()
	if len(got) != 2 || got[0].Path != "/usr/local" || got[1].Path != "/usr/local/bin" || !got[0].External || !got[1].External {
		t.Fatalf("darwin launcher parents = %+v, want external /usr/local then /usr/local/bin", got)
	}
	linux := newTestHost(t, "linux")
	if got := linux.env.launcherParentDirs(); len(got) != 1 || got[0].Path != "/usr/bin" || !got[0].External {
		t.Fatalf("linux launcher parents = %+v, want external /usr/bin", got)
	}
}
