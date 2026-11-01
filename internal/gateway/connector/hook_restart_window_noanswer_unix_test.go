// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestShellHookRestartWindowNoAnswerFollowsTheOutageMode pins rel-1-0-6
// GAP-0295 on the per-user shell hook: the call's first try is refused (this
// account's gateway is restarting, curl/hook-post 7) and the try sent to the
// gateway that comes up gets no answer before the call's budget ends
// (hook-post 9). That is the restart outlasting the budget: the default and
// permissive tiers let the call run with the outage warning and a fail_open
// row, the strict tier blocks it with the restarting text and a fail_closed
// row. A first try that gets no answer with no refusal is still the
// hung-gateway refusal in every mode.
func TestShellHookRestartWindowNoAnswerFollowsTheOutageMode(t *testing.T) {
	for _, tc := range []struct {
		name, outageMode string
		env              []string
		allow            bool
		wantText         string
	}{
		{"refused then no answer, open tier", "open", []string{"DC_COLD_FAILS=1", "DC_COLD_FIRST_RC=7", "DC_COLD_DROP_LISTENER=1", "DC_COLD_THEN_RC=9"}, true, "restarting or not running"},
		{"refused then no answer, strict tier", "closed", []string{"DC_COLD_FAILS=1", "DC_COLD_FIRST_RC=7", "DC_COLD_DROP_LISTENER=1", "DC_COLD_THEN_RC=9"}, false, "restarting or not running"},
		{"no answer with no refusal, open tier", "open", []string{"DC_COLD_FAILS=1000", "DC_COLD_FIRST_RC=9"}, false, "the gateway is running but did not answer"},
		// hook-post 10: no answer while a start or restart of this account's
		// gateway holds its start lock (the old gateway is stopping, or the
		// new one is not ready): the restart outage, with no refusal first.
		{"no answer during a restart, open tier", "open", []string{"DC_COLD_FAILS=1000", "DC_COLD_FIRST_RC=10"}, true, "restarting or not running"},
		{"no answer during a restart, strict tier", "closed", []string{"DC_COLD_FAILS=1000", "DC_COLD_FIRST_RC=10"}, false, "restarting or not running"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := append([]string{"DEFENSECLAW_FAIL_MODE=open", "DC_COLD_OUTAGE_MODE=" + tc.outageMode}, tc.env...)
			// This account's gateway process is alive (the one that is coming
			// up, or a hung one).
			alive := func(dataDir string) {
				_ = os.WriteFile(filepath.Join(dataDir, "gateway.pid"), []byte(strconv.Itoa(os.Getpid())+"\n"), 0o600)
			}
			run := runHookForColdStart(t, NewClaudeCodeConnector(), "claude-code-hook.sh", nil, alive, env...)
			if tc.allow {
				if code := exitCodeOf(run.err); code != 0 || strings.Contains(run.stdout, `"deny"`) {
					t.Fatalf("exit %d stdout %q stderr %q, want the call to run", code, run.stdout, run.stderr)
				}
				var notice struct {
					SystemMessage string `json:"systemMessage"`
				}
				if err := json.Unmarshal([]byte(strings.TrimSpace(run.stdout)), &notice); err != nil ||
					!strings.Contains(notice.SystemMessage, tc.wantText) || !strings.Contains(notice.SystemMessage, "is not checking this session") {
					t.Fatalf("stdout %q, want the outage warning naming the restart", run.stdout)
				}
			} else if reason := failClosedDenyReason(t, run); !strings.Contains(reason, tc.wantText) {
				t.Fatalf("deny reason %q, want %q", reason, tc.wantText)
			}
			// hook-post is told the data directory where a restart holds
			// its start lock: the parent of the hook's own folder.
			if got, want := readColdStartCapture(t, run.capDir, "datadir.1"), filepath.Dir(resolvedPath(t, run.hooksDir)); got != want {
				t.Fatalf("hook-post data directory %q, want %q", got, want)
			}
			records := hookFailureRecords(t, run.dataDir)
			if len(records) != 1 {
				t.Fatalf("hook-failures rows %+v, want one", records)
			}
			want := "fail_closed"
			if tc.allow {
				want = "fail_open"
			}
			if got := records[0]["outcome"]; got != want {
				t.Fatalf("row %+v, want outcome %s (the answer the call got)", records[0], want)
			}
		})
	}
}

func resolvedPath(t *testing.T, path string) string {
	t.Helper()
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatal(err)
	}
	return resolved
}

// TestShellHookRefusedWhileItsGatewayComesUpIsTheRestartOutage pins the last
// part of rel-1-0-6 GAP-0295: the helper's connection is refused, and by the
// time the hook reads the socket tables this account's own gateway listens
// and its process is alive (it is coming up in a restart). The call is not
// sent again (a possibly changed peer gets no credentials); it is the restart
// outage, which the outage mode decides. Before, it was blocked in every mode
// as "the gateway is running but did not answer".
func TestShellHookRefusedWhileItsGatewayComesUpIsTheRestartOutage(t *testing.T) {
	alive := func(dataDir string) {
		_ = os.WriteFile(filepath.Join(dataDir, "gateway.pid"), []byte(strconv.Itoa(os.Getpid())+"\n"), 0o600)
	}
	for _, tc := range []struct {
		outageMode string
		allow      bool
	}{{"open", true}, {"closed", false}} {
		t.Run("outage mode "+tc.outageMode, func(t *testing.T) {
			run := runHookForColdStart(t, NewClaudeCodeConnector(), "claude-code-hook.sh", nil, alive,
				"DEFENSECLAW_FAIL_MODE=open", "DC_COLD_OUTAGE_MODE="+tc.outageMode, "DC_COLD_FAILS=1000", "DC_COLD_FIRST_RC=7")
			if got := strings.TrimSpace(readColdStartCapture(t, run.capDir, "count")); got != "1" {
				t.Fatalf("hook-post ran %q times, want 1: a refused call is not sent to the listener that appeared", got)
			}
			if tc.allow {
				if code := exitCodeOf(run.err); code != 0 || strings.Contains(run.stdout, `"deny"`) || !strings.Contains(run.stdout, "restarting or not running") {
					t.Fatalf("exit %d stdout %q stderr %q, want the call to run with the restart warning", code, run.stdout, run.stderr)
				}
			} else if reason := failClosedDenyReason(t, run); !strings.Contains(reason, "restarting or not running") {
				t.Fatalf("deny reason %q, want the restarting text", reason)
			}
		})
	}
}
