// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package enterpriseunix

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// A pending stop of an account that was removed from the computer is
// dropped by the next ensure, with one change line, instead of a
// sandbox_pending_restart warning on every status, verify and ensure from
// then on (GAP-0155). The gateway's records of the account (which made the
// lifecycle think a daemon had run) stay. A lookup that fails another way
// (a directory outage) keeps the change waiting.
func TestPendingStopOfARemovedAccountIsDropped(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newOSHost(t, goos)
			on := sandboxConfig(t, goos, true, map[string]any{"install": "prerequisite", "driver": "docker"})
			requireOK(t, h.ensure(on))
			gone := SandboxAccount{Name: "r106gone", UID: h.alice.UID + 7, Home: "/home/r106gone"}
			down := SandboxAccount{Name: "r106down", UID: h.alice.UID + 8, Home: "/home/r106down"}
			for _, a := range []SandboxAccount{gone, down} {
				h.ops.accounts = append(h.ops.accounts, a)
				h.ops.status[a.UID] = SandboxStatus{Active: true, Running: 1}
				// The managed gateway's registrations of the account.
				dir := h.env.P(filepath.Join(h.env.Layout.DataDir, "sandbox", "registrations"))
				if err := os.MkdirAll(dir, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, strconv.Itoa(a.UID)+".json"), []byte(`{"v":1}`), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			off := sandboxConfig(t, goos, false, nil)
			requireOK(t, h.ensure(off))
			for _, a := range []SandboxAccount{gone, down} {
				if entry := h.env.loadOpenShellState().Pending[fmt.Sprint(a.UID)]; entry.Kind != "stop" {
					t.Fatalf("%s: no pending stop: %+v", a.Name, entry)
				}
			}
			// Both accounts' daemons stop answering; one was removed.
			for _, a := range []SandboxAccount{gone, down} {
				delete(h.ops.status, a.UID)
				h.ops.statusErr[a.UID] = errors.New("runuser: user " + a.Name + " does not exist")
			}
			if goos == "darwin" {
				h.reply(map[string]fakeReply{
					"dscl . -read /Users/" + gone.Name + " UniqueID": {result: CommandResult{ExitCode: 56}, err: errors.New("dscl: eDSRecordNotFound")},
					"dscl . -read /Users/" + down.Name + " UniqueID": {result: CommandResult{ExitCode: 1}, err: errors.New("dscl: DS Error: -14987 (eServerNotRunning)")},
				})
			} else {
				h.reply(map[string]fakeReply{
					"getent passwd " + strconv.Itoa(gone.UID): {result: CommandResult{ExitCode: 2}, err: errors.New("getent: exit 2")},
					"getent passwd " + strconv.Itoa(down.UID): {result: CommandResult{ExitCode: 1}, err: errors.New("getent: exit 1")},
				})
			}
			r := h.ensure(off)
			requireOK(t, r)
			pending := h.env.loadOpenShellState().Pending
			if _, waiting := pending[fmt.Sprint(gone.UID)]; waiting || !containsLine(r.Changes, "dropped the pending stop change of "+gone.Name) {
				t.Fatalf("the removed account still waits: %+v changes %v", pending, r.Changes)
			}
			if _, waiting := pending[fmt.Sprint(down.UID)]; !waiting {
				t.Fatalf("an account whose lookup failed stopped waiting: %+v", pending)
			}
			r = h.ensure(off)
			requireOK(t, r)
			if w := messagesOf(r.Warnings, codeSandboxPending); strings.Contains(w, gone.Name) {
				t.Fatalf("the next run warns about the removed account: %q", w)
			}
		})
	}
}

// reply adds answers to the host's fake runner.
func (h *osHost) reply(replies map[string]fakeReply) {
	if h.runner.replies == nil {
		h.runner.replies = map[string]fakeReply{}
	}
	for k, v := range replies {
		h.runner.replies[k] = v
	}
}
