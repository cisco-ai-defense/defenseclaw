// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package openshell

import (
	"strconv"
	"strings"
	"testing"
)

func TestParseLaunchAgentStateAndFailure(t *testing.T) {
	for _, tc := range []struct {
		name, state, reason, code, spawn, want, notice string
		runs, expected                                 int
	}{
		{name: "code signing kill", state: "not running", reason: "OS_REASON_CODESIGNING", code: "(never exited)", runs: 5, want: "code signing"},
		{name: "code signing spawn error", state: "not running", spawn: "CodeSigning validation failed", runs: 1, want: "code signing"},
		{name: "other failed spawn", state: "not running", spawn: "permission denied", runs: 1, want: "last spawn error"},
		{name: "prerequisite exit", state: "not running", code: "78: EX_CONFIG", runs: 1, notice: "prerequisite of this account"},
		{name: "other idle exit", state: "not running", code: "1", runs: 1, notice: "last exit code 1"},
		{name: "idle after launchd reset", state: "not running", code: "(never exited)", runs: 3},
		{name: "idle before first start", state: "not running", code: "(never exited)", runs: 0},
		{name: "cleanly idle", state: "not running", code: "0", runs: 1},
		{name: "running after older signing kill", state: "running", reason: "OS_REASON_CODESIGNING", runs: 6},
		{name: "expected to run", state: "not running", code: "0", runs: 1, expected: 1, want: "must be running"},
		{name: "expected to run after prerequisite exit", state: "not running", code: "78", runs: 1, expected: 1, want: "must be running", notice: "prerequisite of this account"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := []byte("gui/503/com.cisco.defenseclaw.openshell-gateway = {\n\tstate = " + tc.state + "\n\truns = " + strconv.Itoa(tc.runs) + "\n\tlast exit reason = " + tc.reason + "\n\tlast exit code = " + tc.code + "\n\tlast spawn error = " + tc.spawn + "\n}\n")
			got := ParseLaunchAgentState(raw)
			if got.State != tc.state || got.Runs != tc.runs || got.ExitReason != tc.reason || got.ExitCode != tc.code || got.SpawnError != tc.spawn {
				t.Fatalf("parse = %+v", got)
			}
			if failure := got.Failure(tc.expected != 0); tc.want == "" && failure != "" || tc.want != "" && !strings.Contains(failure, tc.want) {
				t.Fatalf("failure = %q, want %q", failure, tc.want)
			}
			if notice := got.Notice(); tc.notice == "" && notice != "" || tc.notice != "" && !strings.Contains(notice, tc.notice) {
				t.Fatalf("notice = %q, want %q", notice, tc.notice)
			}
		})
	}
}
