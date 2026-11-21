// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestWindowsHookCMDSpellingOfAHomeFileIsTheWrittenOutPath copies the home
// Git credential file of the active user with the home written out and with
// cmd's %USERPROFILE% spelling, through the exec tool (a shell the hook does
// not name) in every pack: the call is placed in PowerShell, which reads
// %USERPROFILE% as a relative folder name, so before rel-1-0-10:GAP-0999 the
// cmd spelling alerted at MEDIUM (allowed on Windows) while the written-out
// path blocked in strict. Both get the same verdict and rule now, and a copy
// of an ordinary file under %USERPROFILE% stays allowed with no finding.
func TestWindowsHookCMDSpellingOfAHomeFileIsTheWrittenOutPath(t *testing.T) {
	previous := windowsHookHost
	windowsHookHost = func() bool { return true }
	t.Cleanup(func() { windowsHookHost = previous })
	const home = `C:\Users\alice`
	sameHostHomeForTest = home
	t.Cleanup(func() { sameHostHomeForTest = "" })
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	inspect := func(server *APIServer, command string) (string, []string) {
		t.Helper()
		body, err := json.Marshal(map[string]any{"tool": "exec", "connector": "openclaw",
			"args": map[string]any{"command": command, "workdir": home + `\proj`}})
		if err != nil {
			t.Fatal(err)
		}
		recorder := httptest.NewRecorder()
		server.handleInspectTool(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/inspect/tool", bytes.NewReader(body)))
		var verdict ToolInspectVerdict
		if recorder.Code != http.StatusOK || json.Unmarshal(recorder.Body.Bytes(), &verdict) != nil {
			t.Fatalf("%s: status %d body %s", command, recorder.Code, recorder.Body.String())
		}
		return verdict.Action, verdict.Findings
	}
	const rule = "PATH-GIT-CREDS"
	hasRule := func(findings []string) bool {
		for _, finding := range findings {
			if finding == rule || strings.HasPrefix(finding, rule+":") {
				return true
			}
		}
		return false
	}
	for _, pack := range gap0437Packs {
		server := gap0437Server(t, pack, "openclaw", "action")
		wantAction, wantFindings := inspect(server, `copy `+home+`\.git-credentials C:\t`)
		if !hasRule(wantFindings) {
			t.Fatalf("%s: the written-out path has no %s: %s %v", pack.name, rule, wantAction, wantFindings)
		}
		if got, findings := inspect(server, `copy %USERPROFILE%\.git-credentials C:\t`); got != wantAction || !hasRule(findings) {
			t.Errorf("%s: %%USERPROFILE%% spelling: %s %v, want %s with %s (the written-out path)",
				pack.name, got, findings, wantAction, rule)
		}
		if got, findings := inspect(server, `copy %USERPROFILE%\notes\a.txt C:\t`); got != "allow" || len(findings) != 0 {
			t.Errorf("%s: ordinary file under %%USERPROFILE%%: %s %v, want allow with no finding", pack.name, got, findings)
		}
	}
}
