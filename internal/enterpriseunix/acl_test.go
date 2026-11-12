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
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// linkedSnapshotACLRunner models macOS ACLs on two names of the same inode.
// Removing an entry through either name removes it through the other.
type linkedSnapshotACLRunner struct {
	*fakeRunner
	source string
	blob   string
}

func (r linkedSnapshotACLRunner) Run(ctx context.Context, name string, args ...string) (CommandResult, error) {
	result, err := r.fakeRunner.Run(ctx, name, args...)
	if err == nil && name == "chmod" && len(args) == 4 && args[1] == "-a#" {
		other := ""
		switch args[3] {
		case r.source:
			other = r.blob
		case r.blob:
			other = r.source
		}
		if other != "" {
			r.mu.Lock()
			if entries := r.acls[args[3]]; len(entries) > 0 {
				r.acls[other] = append([]string(nil), entries...)
			} else {
				delete(r.acls, other)
			}
			r.mu.Unlock()
		}
	}
	return result, err
}

// GAP-0664: a private deployment file and its preserved hard link share
// one ACL. Repair must clear the live ACL once and leave a public read ACL.
func TestGAP0664RepairWithLinkedSnapshotACL(t *testing.T) {
	h := newTestHost(t, "darwin")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	canonical := filepath.Join(h.env.Layout.LifecycleDir, deploymentFileName)
	source := h.env.P(canonical)
	snap, err := h.env.takeSnapshot("linked-acl", []string{canonical}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer h.env.discardSnapshot(snap)
	blob := h.env.blobPath(snap, snap.Entries[0])
	sourceInfo, sourceErr := os.Lstat(source)
	blobInfo, blobErr := os.Lstat(blob)
	if sourceErr != nil || blobErr != nil || !os.SameFile(sourceInfo, blobInfo) {
		t.Fatalf("snapshot did not preserve a hard link: source %v, blob %v", sourceErr, blobErr)
	}
	public := h.env.P(filepath.Join(h.env.Layout.BinDir, binHook))
	entry := "group:staff allow read,readattr,readextattr,list,search"
	h.runner.acls = map[string][]string{source: {entry}, blob: {entry}, public: {entry}}
	h.env.Runner = linkedSnapshotACLRunner{fakeRunner: h.runner, source: source, blob: blob}
	requireOK(t, h.run(Options{Action: ActionRepair}))
	if len(h.runner.acls[source]) != 0 || len(h.runner.acls[blob]) != 0 {
		t.Fatalf("repair kept the private file ACL: %v", h.runner.acls)
	}
	if got := h.runner.acls[public]; len(got) != 1 || got[0] != entry {
		t.Fatalf("repair changed a public read ACL: %v", got)
	}
	for _, target := range h.env.aclTargets([]string{canonical}, nil) {
		if target.path == blob {
			t.Fatal("snapshot hard link was selected for ACL repair")
		}
	}
	h.env.discardSnapshot(snap)
	writeFreshLedger(t, h)
	requireOK(t, h.run(Options{Action: ActionVerify}))
}

// GAP-0664: other private names of an inode must be checked, while repair
// removes each shared ACL entry only once.
func TestGAP0664RepairCoalescesHardlinkACLs(t *testing.T) {
	for _, tc := range []struct {
		name  string
		entry string
	}{
		{"read", "group:staff allow read,readattr,readextattr,list,search"},
		{"write", "user:developer allow write,append"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newTestHost(t, "darwin")
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
			canonical := filepath.Join(h.env.Layout.LifecycleDir, deploymentFileName)
			source := h.env.P(canonical)
			alias := h.env.P(filepath.Join(h.env.Layout.LifecycleDir, "linked-record"))
			if err := os.Link(source, alias); err != nil {
				t.Fatal(err)
			}
			sourceInfo, sourceErr := os.Lstat(source)
			aliasInfo, aliasErr := os.Lstat(alias)
			if sourceErr != nil || aliasErr != nil || !os.SameFile(sourceInfo, aliasInfo) {
				t.Fatalf("expected the same inode: source %v, alias %v", sourceErr, aliasErr)
			}
			selected := map[string]bool{source: false, alias: false}
			for _, target := range h.env.aclTargets([]string{canonical}, nil) {
				if _, ok := selected[target.path]; ok {
					selected[target.path] = true
				}
			}
			for path, ok := range selected {
				if !ok {
					t.Fatalf("private ACL target omitted: %s", path)
				}
			}
			public := h.env.P(filepath.Join(h.env.Layout.BinDir, binHook))
			publicRead := "group:staff allow read,readattr"
			h.runner.acls = map[string][]string{
				source: {tc.entry}, alias: {tc.entry}, public: {publicRead},
			}
			h.env.Runner = linkedSnapshotACLRunner{fakeRunner: h.runner, source: source, blob: alias}
			requireOK(t, h.run(Options{Action: ActionRepair}))
			if len(h.runner.acls[source]) != 0 || len(h.runner.acls[alias]) != 0 {
				t.Fatalf("repair kept the private file ACL: %v", h.runner.acls)
			}
			if got := h.runner.acls[public]; len(got) != 1 || got[0] != publicRead {
				t.Fatalf("repair changed the public read ACL: %v", got)
			}
			removals := 0
			for _, call := range h.runner.calls {
				if strings.Contains(call, "chmod -h -a#") &&
					(strings.HasSuffix(call, " "+source) || strings.HasSuffix(call, " "+alias)) {
					removals++
				}
			}
			if removals != 1 {
				t.Fatalf("shared ACL entry removed %d times, want 1", removals)
			}
			writeFreshLedger(t, h)
			requireOK(t, h.run(Options{Action: ActionVerify}))
		})
	}
}

func TestGAP0664HardlinkKeepsStricterPathPolicy(t *testing.T) {
	h := newTestHost(t, "darwin")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	source := h.env.P(filepath.Join(h.env.Layout.LifecycleDir, deploymentFileName))
	alias := h.env.P(filepath.Join(h.env.Layout.LifecycleDir, "linked-record"))
	if err := os.Link(source, alias); err != nil {
		t.Fatal(err)
	}
	read := "group:staff allow read,readattr"
	write := "user:developer allow write,append"
	h.runner.acls = map[string][]string{source: {read, write}, alias: {read, write}}
	h.env.Runner = linkedSnapshotACLRunner{fakeRunner: h.runner, source: source, blob: alias}
	l := &lifecycle{env: h.env, opts: Options{Action: ActionRepair}}
	// The first path allows read. The second requires its removal, so the
	// shared inode must lose both indexed entries.
	if err := l.removeACLTargets(context.Background(), []aclTarget{
		{path: alias, private: false},
		{path: source, private: true},
	}); err != nil {
		t.Fatal(err)
	}
	if len(h.runner.acls[source]) != 0 || len(h.runner.acls[alias]) != 0 {
		t.Fatalf("the private path retained an ACL entry: %v", h.runner.acls)
	}
}

func TestGAP0664SnapshotDirectoriesClearInheritedACL(t *testing.T) {
	h := newTestHost(t, "darwin")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	store := h.env.P(filepath.Join(h.env.Layout.LifecycleDir, snapshotsDirName))
	if err := os.MkdirAll(store, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(store, 0o755); err != nil {
		t.Fatal(err)
	}
	h.runner.acls = map[string][]string{store: {"group:staff allow read,search"}}
	snap, err := h.env.takeSnapshot("inherited-acl", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer h.env.discardSnapshot(snap)
	if len(h.runner.acls[store]) != 0 {
		t.Fatalf("snapshot store retained an inherited ACL: %v", h.runner.acls[store])
	}
	if info, err := os.Lstat(store); err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("snapshot store mode = %v, %v; want 0700", info, err)
	}
	for _, path := range []string{store, snap.Dir, filepath.Join(snap.Dir, "files")} {
		if !strings.Contains(strings.Join(h.runner.calls, "\n"), "chmod -h -N "+path) {
			t.Errorf("snapshot directory %s was not cleared before storing files", path)
		}
	}
}

// failingLsRunner fails every ls that lists path.
type failingLsRunner struct {
	Runner
	path string
}

func (r failingLsRunner) Run(ctx context.Context, name string, args ...string) (CommandResult, error) {
	if name == "ls" && strings.Contains(strings.Join(args, "\x00"), r.path) {
		return CommandResult{ExitCode: 1}, errors.New("ls: permission denied")
	}
	return r.Runner.Run(ctx, name, args...)
}

// GAP-0034: repair removed the whole ACL (chmod -N) of a policy folder with
// a harmful entry, so an administrator's unrelated read entry on the Claude
// Code managed-settings.d went too. Only the deny and write entries go.
func TestRepairKeepsUnrelatedMacOSACLEntriesOfAPolicyFolder(t *testing.T) {
	h := newTestHost(t, "darwin")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0"), ConfigFile: machinePolicyConfig(t, h, "claudecode")}))
	dir := h.env.P("/Library/Application Support/ClaudeCode/managed-settings.d")
	h.runner.acls = map[string][]string{dir: {
		"group:everyone deny search", "user:dcm-std1 allow add_file", "user:ec2-user allow list,readattr",
	}}
	requireOK(t, h.run(Options{Action: ActionRepair}))
	if got := h.runner.acls[dir]; len(got) != 1 || got[0] != "user:ec2-user allow list,readattr" {
		t.Fatalf("after repair the ACL of managed-settings.d is %v, want only the unrelated read entry", got)
	}
	requireOK(t, h.run(Options{Action: ActionStatus}))
}

// GAP-1458: an ACL entry on /Library/Application Support that lets a
// standard user add or delete a folder let that user put another ClaudeCode
// folder in place of the protected one; the ancestor trust check read only
// the owner and mode. Status names it and repair refuses it (and leaves the
// system folder alone); entries for administrators or read-only entries pass,
// and an ACL that cannot be read fails closed.
func TestMachinePolicyAncestorACLsMustNotLetStandardUsersWrite(t *testing.T) {
	h := newTestHost(t, "darwin")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0"), ConfigFile: machinePolicyConfig(t, h, "claudecode")}))
	ancestor := "/Library/Application Support"
	rooted := h.env.P(ancestor)
	for _, entry := range []string{
		"group:admin allow add_subdirectory,delete_child",
		"user:developer allow read,search,readattr",
		"group:everyone deny delete",
	} {
		h.runner.acls = map[string][]string{rooted: {entry}}
		requireOK(t, h.run(Options{Action: ActionStatus}))
	}
	for _, entry := range []string{"user:developer allow add_subdirectory", "group:staff inherited allow delete_child"} {
		h.runner.acls = map[string][]string{rooted: {entry}}
		if got := messagesOf(h.run(Options{Action: ActionStatus}).Errors, codeVerify); !strings.Contains(got, ancestor) || !strings.Contains(got, entry) {
			t.Fatalf("status did not name %q on %s: %s", entry, ancestor, got)
		}
	}
	if repair := h.run(Options{Action: ActionRepair}); repair.OK || h.runner.acls[rooted] == nil || !strings.Contains(fmt.Sprint(repair.Errors), "chmod -a") {
		t.Fatalf("repair accepted or removed the entry on %s: %+v", ancestor, repair)
	}
	h.runner.acls = nil
	h.env.Runner = failingLsRunner{Runner: h.env.Runner, path: rooted}
	if status := h.run(Options{Action: ActionStatus}); !strings.Contains(messagesOf(status.Errors, codeVerify), "could not be read") {
		t.Fatalf("status accepted an ACL it could not read: %+v", status)
	}
	if repair := h.run(Options{Action: ActionRepair}); repair.OK {
		t.Fatalf("repair accepted an ACL it could not read: %+v", repair)
	}
}

func TestGatewayConfigReadDenyACLIsRemovedBeforeApply(t *testing.T) {
	for _, target := range []struct {
		path  func(*testHost) string
		entry string
	}{
		{func(h *testHost) string { return h.env.P(h.env.Layout.ConfigPath) }, "user:_defenseclaw deny read"},
		{func(h *testHost) string { return h.env.P(h.env.Layout.ConfigDir) }, "user:_defenseclaw deny search"},
	} {
		h := newTestHost(t, "darwin")
		requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
		path := target.path(h)
		h.runner.acls = map[string][]string{path: {target.entry}}
		if got := messagesOf(h.run(Options{Action: ActionStatus}).Errors, codeVerify); !strings.Contains(got, target.entry) {
			t.Fatalf("status missed gateway read denial at %s: %s", path, got)
		}
		requireOK(t, h.run(Options{Action: ActionRepair}))
		if len(h.runner.acls[path]) != 0 {
			t.Fatalf("repair left gateway read denial at %s: %v", path, h.runner.acls[path])
		}
	}
}
