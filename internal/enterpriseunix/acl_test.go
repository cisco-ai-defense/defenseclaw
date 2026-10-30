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
	"strings"
	"testing"
)

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
