// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"testing"
)

// TestR105ManagedLinkThenArchiveCopyIsAProjectCopy is GAP-2582: behind
// ProtectHome a benign project link followed by cp -a of a project
// directory (plain or in a literal sh -c body) was blocked as an SSH
// authorized-keys mutation. The gateway could not stat the source, so it
// read the archive copy as a file write to its destination, and the link
// made the destination's copy scope opaque, so the client's resolved answer
// was ignored. Every link or copy twin that reaches authorized_keys still
// blocks, with and without a key link already in the project.
func TestR105ManagedLinkThenArchiveCopyIsAProjectCopy(t *testing.T) {
	type row struct {
		id, command         string
		block, needsKeyLink bool
	}
	rows := []row{
		{"N03", `sh -c "ln -s build/out bin && cp -a build dist"`, false, false},
		{"N04", `ln -s build/out bin; sh -c "cp -a src dist"; echo x > notes.txt`, false, false},
		{"N03p", `ln -s build/out bin && cp -a build dist`, false, false},
		{"N04p", `ln -s build/out bin; cp -a src dist; echo x > notes.txt`, false, false},
		{"B02", `ln -s build/out bin; cp -a src dist; cp -a build dist2`, false, false},
		{"B03", `ln -sf ../src/a.txt link.txt && cp -a src out`, false, false},
		{"B05", `ln -s build/out bin && cp --archive build dist`, false, false},
		{"B06", `ln -s build/out bin && cp -r build dist`, false, false},
		{"T02", `sh -c "ln -s ../.ssh k && cp -a src/a.txt k/authorized_keys"`, true, false},
		{"T03", `ln -s ../.ssh k; sh -c "cp -a src/a.txt k/authorized_keys"`, true, false},
		{"T04", `ln -s ../.ssh/authorized_keys k; sh -c "cp -a src/a.txt k"`, true, false},
		{"T05", `ln -s ../.ssh/authorized_keys k; cp -a src/a.txt k`, true, false},
		{"T06", `ln -s ../.ssh/authorized_keys k && cp --archive src/a.txt k`, true, false},
		{"T07", `ln -s ../.ssh/authorized_keys k && cp -r src/a.txt k`, true, false},
		{"T08", `ln -s ../.ssh k && cp -a src/a.txt k/authorized_keys`, true, false},
		{"T10", `ln -s ../.ssh/authorized_keys k; cp -a k dist; echo key >> dist`, true, false},
		{"T13", `ln -s ../.ssh k; cp -a build dist; cp -a src/a.txt k/authorized_keys`, true, false},
		{"T14", `ln -s ../.ssh k; cp -a k dist; echo key >> dist/authorized_keys`, true, false},
		{"T15", `ln -s ../../.ssh build/k; cp -a build dist; echo key >> dist/k/authorized_keys`, true, false},
		{"T16", `ln -s ../.ssh k; mv k build/k; cp -a build dist; echo key >> dist/k/authorized_keys`, true, false},
		{"T17", `sh -c "ln -s ../../.ssh build/k && cp -a build dist"; echo key >> dist/k/authorized_keys`, true, false},
		{"T18", `cd build && ln -s ../../.ssh k && cd .. && cp -a build dist && echo key >> dist/k/authorized_keys`, true, false},
		{"T19", `ln -s ../.ssh k; cp -a k src dist; echo key >> dist/k/authorized_keys`, true, false},
		{"T11", `cp -a keylink dist2; echo key >> dist2`, true, true},
		{"T12", `cp -a src/a.txt keylink`, true, true},
	}
	for _, keyLink := range []bool{false, true} {
		f := newB36ManagedHookFixture(t)
		if !keyLink {
			if err := os.Remove(filepath.Join(f.project, "keylink")); err != nil {
				t.Fatal(err)
			}
		}
		for _, dir := range []string{"build/out", "src"} {
			if err := os.MkdirAll(filepath.Join(f.project, dir), 0o700); err != nil {
				t.Fatal(err)
			}
		}
		for _, name := range []string{"a.txt", "src/a.txt", "build/x.o"} {
			if err := os.WriteFile(filepath.Join(f.project, name), []byte("x\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		for _, r := range rows {
			if r.needsKeyLink && !keyLink {
				continue
			}
			want := "allow"
			if r.block {
				want = "block"
			}
			for _, connector := range []string{"claudecode", "codex"} {
				payload := f.payload(t, r.command)
				if got := f.post(t, connector, payload, f.clientHeader(t, payload)); got != want {
					t.Errorf("keylink=%t %s/%s: verdict %s, want %s: %s", keyLink, connector, r.id, got, want, r.command)
				}
			}
		}
	}
}
