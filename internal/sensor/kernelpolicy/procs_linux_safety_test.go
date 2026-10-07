//go:build linux

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package kernelpolicy

import "testing"

func TestScanProcsDoesNotGuessTheHostPIDNamespace(t *testing.T) {
	root := t.TempDir()
	writeProc(t, root, fakeProc{pid: 4001, ppid: 1, uid: 1001, euid: 1001,
		comm: "claude", ticks: 100, exe: aliceClaudeNew, cmdline: []string{aliceClaudeNew}})
	procs, err := ScanProcs(root, func(uid int) bool { return uid == 1001 })
	if err != nil {
		t.Fatal(err)
	}
	if len(procs) != 1 || procs[0].Host {
		t.Fatalf("an unreadable namespace cannot authorize a host PID anchor: %+v", procs)
	}
}
