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

package enterprisepolicy

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// Every user's agent reads machine policy, so a policy file DefenseClaw
// published is 0644. An administrator who tightens one (0600 on
// /etc/codex/requirements.toml makes every standard user's Codex refuse to
// start) fails verify, which does not report the connector in place, so the
// lifecycle's ensure re-applies; the next publish restores the mode.
func TestVerifyRequiresThePublishedModeOfOwnedPolicyFiles(t *testing.T) {
	withHigherSources(t)
	connectors := []string{"claudecode", "codex", "copilot", "cursor"}
	for _, name := range connectors {
		t.Run(name, func(t *testing.T) {
			opts := publishTestOptions(t)
			if _, err := Publish(opts, connectors); err != nil {
				t.Fatal(err)
			}
			var files []string
			for _, recordName := range []string{name, claudeVersionFloorRecord} {
				if recordName == claudeVersionFloorRecord && name != "claudecode" {
					continue
				}
				record, err := loadRecord(opts, recordName)
				if err != nil || record == nil {
					t.Fatalf("%s record: %v %v", recordName, record, err)
				}
				files = append(files, record.Path)
			}
			for _, file := range files {
				if err := os.Chmod(file, 0o600); err != nil {
					t.Fatal(err)
				}
			}

			verify, err := VerifyAll(opts, connectors)
			if err != nil {
				t.Fatal(err)
			}
			if containsString(verify.MachinePolicyConnectors, name) {
				t.Fatalf("a connector whose policy file agents cannot read is not in place: %v", verify.MachinePolicyConnectors)
			}
			for _, state := range verify.States {
				if state.Connector != name {
					continue
				}
				if state.Covered || !hasConflict(state, "mode 0600") || !hasConflict(state, files[0]) {
					t.Fatalf("verify must name the file and its mode: covered=%v %v", state.Covered, state.Conflicts)
				}
			}

			if _, err := Publish(opts, connectors); err != nil {
				t.Fatal(err)
			}
			for _, file := range files {
				info, err := os.Stat(file)
				if err != nil || info.Mode().Perm() != 0o644 {
					t.Fatalf("the next publish must restore %s to 0644: %v %v", file, info.Mode(), err)
				}
			}
			verify, err = VerifyAll(opts, connectors)
			if err != nil || !containsString(verify.MachinePolicyConnectors, name) {
				t.Fatalf("after the repair the connector is in place: %v %v", verify.MachinePolicyConnectors, err)
			}
			for _, state := range verify.States {
				if state.Connector == name && (!state.Covered || strings.Contains(strings.Join(state.Conflicts, "\n"), "mode 0")) {
					t.Fatalf("after the repair verify passes: %v", state.Conflicts)
				}
			}
		})
	}
}

// A macOS deny ACL on the managed drop-in directory leaves mode 0755 intact
// while preventing standard users from loading the hooks.
func TestVerifyAndRestorePublishedDirWithMacOSDenyACL(t *testing.T) {
	withHigherSources(t)
	opts := publishTestOptions(t)
	opts.GOOS = "darwin"
	if _, err := Publish(opts, []string{"claudecode"}); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(opts.Root, "Library/Application Support/ClaudeCode/managed-settings.d")
	denied := true
	previousRead, previousClear := publishedDirACLEntries, clearPublishedDirACL
	t.Cleanup(func() { publishedDirACLEntries, clearPublishedDirACL = previousRead, previousClear })
	publishedDirACLEntries = func(path string) ([]managed.DarwinACLEntry, error) {
		if path != dir || !denied {
			return nil, nil
		}
		return []managed.DarwinACLEntry{{Text: "group:everyone deny list,search", Rights: []string{"list", "search"}}}, nil
	}
	clearPublishedDirACL = func(path string) error {
		if path != dir {
			t.Fatalf("cleared unexpected ACL on %s", path)
		}
		denied = false
		return nil
	}
	result, err := VerifyAll(opts, []string{"claudecode"})
	if err != nil {
		t.Fatal(err)
	}
	for _, state := range result.States {
		if state.Connector == "claudecode" && (state.Covered || !hasConflict(state, "macOS ACL")) {
			t.Fatalf("denied managed directory reported covered: %+v", state)
		}
	}
	restored, err := RestorePublishedPolicyDirs(opts)
	if err != nil || !containsString(restored, dir) || denied {
		t.Fatalf("restore published dirs = %v, %v; denied=%v", restored, err, denied)
	}
	result, err = VerifyAll(opts, []string{"claudecode"})
	if err != nil || !containsString(result.MachinePolicyConnectors, "claudecode") {
		t.Fatalf("verify after ACL repair: %+v, %v", result, err)
	}
}

// GAP-1350: a Linux named-user ACL entry without search on the 0755
// managed-settings directory keeps that user's Claude Code from loading the
// policy while the mode bits look right. Verify reports it and the restore
// removes the ACL.
func TestVerifyAndRestorePublishedDirWithLinuxDenyACL(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("POSIX ACL xattrs are Linux-only")
	}
	withHigherSources(t)
	opts := publishTestOptions(t)
	if _, err := Publish(opts, []string{"claudecode"}); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(opts.Root, "etc/claude-code/managed-settings.d")
	acl := binary.LittleEndian.AppendUint32(nil, 2)
	for _, e := range [][3]uint32{{0x01, 7, 0xffffffff}, {0x02, 0, 54321}, {0x04, 5, 0xffffffff}, {0x10, 5, 0xffffffff}, {0x20, 5, 0xffffffff}} {
		acl = binary.LittleEndian.AppendUint16(acl, uint16(e[0]))
		acl = binary.LittleEndian.AppendUint16(acl, uint16(e[1]))
		acl = binary.LittleEndian.AppendUint32(acl, e[2])
	}
	if err := unix.Setxattr(dir, "system.posix_acl_access", acl, 0); errors.Is(err, unix.ENOTSUP) {
		t.Skipf("no POSIX ACLs on %s", dir)
	} else if err != nil {
		t.Fatal(err)
	}
	result, err := VerifyAll(opts, []string{"claudecode"})
	if err != nil {
		t.Fatal(err)
	}
	for _, state := range result.States {
		if state.Connector == "claudecode" && (state.Covered || !hasConflict(state, "user:54321:---")) {
			t.Fatalf("a managed directory a named user cannot search was reported covered: %+v", state)
		}
	}
	restored, err := RestorePublishedPolicyDirs(opts)
	if err != nil || !containsString(restored, dir) {
		t.Fatalf("restore published dirs = %v, %v", restored, err)
	}
	result, err = VerifyAll(opts, []string{"claudecode"})
	if err != nil || !containsString(result.MachinePolicyConnectors, "claudecode") {
		t.Fatalf("verify after ACL repair: %+v, %v", result, err)
	}
}
