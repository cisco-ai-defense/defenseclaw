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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/posixacl"
)

// publishedFolderConnectors are connectors whose machine policy goes into a
// vendor folder on Linux and macOS: a drop-in folder Claude Code and Copilot
// list, and the Codex folder of a file opened by name.
var publishedFolderConnectors = []string{ConnectorClaudeCode, ConnectorCopilot, ConnectorCodex}

// publishedFolderOf is the folder DefenseClaw published connector's policy
// file into.
func publishedFolderOf(t *testing.T, opts Options, connector string) string {
	t.Helper()
	record, err := loadRecord(opts, connector)
	if err != nil || record == nil {
		t.Fatalf("%s ownership record: %v, %v", connector, record, err)
	}
	return filepath.Dir(platformPath(opts, record.Path))
}

// aclWriteEntriesOf lists the entries of acl with write other than the
// owner's: named users and groups, the owning group and the mask.
func aclWriteEntriesOf(acl posixacl.View) []string {
	if !acl.Present {
		return nil
	}
	var entries []string
	for _, entry := range append(append([]posixacl.Entry(nil), acl.Users...), acl.Groups...) {
		if entry.Perm&0o2 != 0 {
			entries = append(entries, fmt.Sprintf("%s:%d", entry.Kind, entry.ID))
		}
	}
	if acl.Group&0o2 != 0 {
		entries = append(entries, "group::")
	}
	if len(acl.Users)+len(acl.Groups) > 0 && acl.Mask&0o2 != 0 {
		entries = append(entries, "mask::")
	}
	return entries
}

// stateOf is connector's state in result.
func stateOf(t *testing.T, result Result, connector string) State {
	t.Helper()
	for _, state := range result.States {
		if state.Connector == connector {
			return state
		}
	}
	t.Fatalf("no %s state in %+v", connector, result)
	return State{}
}

// assertWriteReportedNotCovered checks that verify reports connector not
// covered, naming want, and leaves it out of the connectors in place.
func assertWriteReportedNotCovered(t *testing.T, opts Options, connector, want string) {
	t.Helper()
	result, err := VerifyAll(opts, []string{connector})
	if err != nil {
		t.Fatal(err)
	}
	state := stateOf(t, result, connector)
	if state.Covered || !state.Drift || !hasConflict(state, "other accounts can write") || !hasConflict(state, want) {
		t.Fatalf("verify of a %s folder another account can write (%s) = covered %v, drift %v, conflicts %q; want not covered, naming it",
			connector, want, state.Covered, state.Drift, state.Conflicts)
	}
	if containsString(result.MachinePolicyConnectors, connector) {
		t.Fatalf("%s is in place while another account can write its folder: %v", connector, result.MachinePolicyConnectors)
	}
}

// assertCoveredAndRepairNoop checks that verify reports connector covered
// and a further publish changes nothing.
func assertCoveredAndRepairNoop(t *testing.T, opts Options, connector string) {
	t.Helper()
	result, err := VerifyAll(opts, []string{connector})
	if err != nil || !containsString(result.MachinePolicyConnectors, connector) || !stateOf(t, result, connector).Covered {
		t.Fatalf("verify after the repair: %+v, %v", result, err)
	}
	again, err := Publish(opts, []string{connector})
	if err != nil || again.Changed {
		t.Fatalf("a second publish after the repair = changed %v, %v; want a no-op", again.Changed, err)
	}
}

// repairs are the two paths that repair a published folder: a lifecycle
// publish (ensure, repair, reconcile) and the hook guardian's pass.
var publishedFolderRepairs = map[string]func(Options, string) error{
	"publish": func(opts Options, connector string) error {
		_, err := Publish(opts, []string{connector})
		return err
	},
	"guardian": func(opts Options, _ string) error {
		_, err := RestorePublishedPolicyDirs(opts)
		return err
	},
}

// GAP-0410 on Linux: a named-user rwx entry on a vendor folder
// (/etc/claude-code/managed-settings.d: mode 0775, mask rwx) was reported
// covered, and the repair only lowered the mask to r-x and kept the entry,
// whose write the next ACL edit makes usable again. verify reports the
// folder not covered, also once the mask holds the write back, and the
// repair removes the named entries with write and the group-class write,
// keeping a read-only named entry, for every vendor folder.
func TestVerifyAndRepairTakeOtherAccountsWriteOffALinuxPolicyFolder(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("POSIX ACL xattrs are Linux-only")
	}
	withHigherSources(t)
	cases := map[string]struct {
		acl  posixacl.View
		want string
	}{
		"named user rwx, mask rwx (mode 0775)": {
			acl: posixacl.View{Present: true, Owner: 7, Group: 5, Mask: 7, Other: 5,
				Users: []posixacl.Entry{{Kind: "user", ID: 54321, Perm: 7}, {Kind: "user", ID: 54322, Perm: 5}}},
			want: "user:54321:rwx",
		},
		"named user rwx held back by mask r-x (mode 0755)": {
			acl: posixacl.View{Present: true, Owner: 7, Group: 5, Mask: 5, Other: 5,
				Users: []posixacl.Entry{{Kind: "user", ID: 54321, Perm: 7}, {Kind: "user", ID: 54322, Perm: 5}}},
			want: "user:54321:rwx",
		},
		"named group -w- and owning group rwx under mask r-x": {
			acl: posixacl.View{Present: true, Owner: 7, Group: 7, Mask: 5, Other: 5,
				Users:  []posixacl.Entry{{Kind: "user", ID: 54322, Perm: 5}},
				Groups: []posixacl.Entry{{Kind: "group", ID: 54400, Perm: 2}}},
			want: "group:54400:-w-",
		},
	}
	for _, connector := range publishedFolderConnectors {
		for name, tc := range cases {
			for repairName, repair := range publishedFolderRepairs {
				t.Run(connector+"/"+name+"/"+repairName, func(t *testing.T) {
					opts := publishTestOptions(t)
					if _, err := Publish(opts, []string{connector}); err != nil {
						t.Fatal(err)
					}
					dir := publishedFolderOf(t, opts, connector)
					if err := unix.Setxattr(dir, linuxAccessACLXattr, linuxAccessACLData(tc.acl), 0); errors.Is(err, unix.ENOTSUP) {
						t.Skipf("no POSIX ACLs on %s", dir)
					} else if err != nil {
						t.Fatal(err)
					}
					assertWriteReportedNotCovered(t, opts, connector, tc.want)
					if err := repair(opts, connector); err != nil {
						t.Fatalf("%s repair: %v", repairName, err)
					}
					info, err := os.Lstat(dir)
					if err != nil {
						t.Fatal(err)
					}
					if perm := info.Mode().Perm(); perm&0o022 != 0 {
						t.Fatalf("%s: mode %04o after the repair; want no group or other write", dir, perm)
					}
					got, err := posixacl.System.Read(dir, info.Mode())
					if err != nil {
						t.Fatal(err)
					}
					if left := aclWriteEntriesOf(got); len(left) > 0 {
						t.Fatalf("%s: ACL entries with write after the repair %v (ACL %+v)", dir, left, got)
					}
					if found, allowed := got.NamedUserAllows(54322, 0o5); !found || !allowed {
						t.Fatalf("%s: the read-only user:54322:r-x entry did not survive the repair: %+v", dir, got)
					}
					if found, _ := got.NamedUserAllows(54321, 0); found {
						t.Fatalf("%s: the user:54321 write entry survived the repair: %+v", dir, got)
					}
					assertCoveredAndRepairNoop(t, opts, connector)
				})
			}
		}
	}
}

// GAP-0410 on macOS: an allow entry with a write right on a vendor folder,
// without any deny next to it, was reported covered and no repair removed
// it (the repair cleared entries only of a folder users could not pass).
// verify reports the folder not covered, and the repair removes the write
// entries and keeps the read-only one, as for GAP-0034.
func TestVerifyAndRepairTakeOtherAccountsWriteOffAMacOSPolicyFolder(t *testing.T) {
	withHigherSources(t)
	for _, connector := range publishedFolderConnectors {
		for repairName, repair := range publishedFolderRepairs {
			t.Run(connector+"/"+repairName, func(t *testing.T) {
				opts := publishTestOptions(t)
				opts.GOOS = "darwin"
				if _, err := Publish(opts, []string{connector}); err != nil {
					t.Fatal(err)
				}
				dir := publishedFolderOf(t, opts, connector)
				acl := []managed.DarwinACLEntry{
					{Index: 0, Text: "user:alice allow list,add_file,search,delete_child", Allow: true, Rights: []string{"list", "add_file", "search", "delete_child"}},
					{Index: 1, Text: "user:ec2-user allow list,readattr", Allow: true, Rights: []string{"list", "readattr"}},
					{Index: 2, Text: "group:staff allow write,file_inherit,directory_inherit", Allow: true, Rights: []string{"write", "file_inherit", "directory_inherit"}},
				}
				previousRead, previousRemove := publishedDirACLEntries, removeDarwinACLEntry
				t.Cleanup(func() { publishedDirACLEntries, removeDarwinACLEntry = previousRead, previousRemove })
				publishedDirACLEntries = func(path string) ([]managed.DarwinACLEntry, error) {
					if path != dir {
						return nil, nil
					}
					return append([]managed.DarwinACLEntry(nil), acl...), nil
				}
				var removed []int
				removeDarwinACLEntry = func(path string, index int) error {
					if path != dir {
						t.Fatalf("removed an ACL entry of %s", path)
					}
					removed = append(removed, index)
					kept := acl[:0:0]
					for _, entry := range acl {
						switch {
						case entry.Index < index:
							kept = append(kept, entry)
						case entry.Index > index:
							entry.Index--
							kept = append(kept, entry)
						}
					}
					acl = kept
					return nil
				}
				assertWriteReportedNotCovered(t, opts, connector, "user:alice allow")
				if err := repair(opts, connector); err != nil {
					t.Fatalf("%s repair: %v", repairName, err)
				}
				if !reflect.DeepEqual(removed, []int{2, 0}) {
					t.Fatalf("removed ACL entries %v, want the two write entries, highest first: [2 0]", removed)
				}
				var left []string
				for _, entry := range acl {
					left = append(left, entry.Text)
				}
				if want := []string{"user:ec2-user allow list,readattr"}; !reflect.DeepEqual(left, want) {
					t.Fatalf("ACL after the repair %q, want %q", left, want)
				}
				if info, err := os.Stat(dir); err != nil || info.Mode().Perm()&0o022 != 0 {
					t.Fatalf("%s after the repair: %v, %v; want no group or other write", dir, info, err)
				}
				assertCoveredAndRepairNoop(t, opts, connector)
			})
		}
	}
}

// GAP-0410: a group- or other-writable vendor folder is reported by verify
// as another account's write, also where trust checks are off (a rooted
// test tree), and the mode repair takes the write away.
func TestVerifyReportsAGroupWritablePolicyFolderModeNotCovered(t *testing.T) {
	withHigherSources(t)
	for _, platform := range []string{"linux", "darwin"} {
		for _, connector := range publishedFolderConnectors {
			t.Run(platform+"/"+connector, func(t *testing.T) {
				opts := publishTestOptions(t)
				opts.GOOS = platform
				if _, err := Publish(opts, []string{connector}); err != nil {
					t.Fatal(err)
				}
				dir := publishedFolderOf(t, opts, connector)
				if err := os.Chmod(dir, 0o775); err != nil {
					t.Fatal(err)
				}
				assertWriteReportedNotCovered(t, opts, connector, dir+" has mode 0775")
				if _, err := Publish(opts, []string{connector}); err != nil {
					t.Fatal(err)
				}
				if info, err := os.Stat(dir); err != nil || info.Mode().Perm() != 0o755 {
					t.Fatalf("%s after the repair: %v, %v; want 0755", dir, info, err)
				}
				assertCoveredAndRepairNoop(t, opts, connector)
			})
		}
	}
}
