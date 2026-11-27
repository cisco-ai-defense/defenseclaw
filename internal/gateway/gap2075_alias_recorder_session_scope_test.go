// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"path/filepath"
	"reflect"
	"testing"
)

// TestGAP2075InspectRouteHoldsAnAliasRecorderOnlyForSessionCalls pins the
// last clause of rel-1-0-10:GAP-2075 (e3bac97b92): the cross-call alias memo
// is keyed by connector, session and home, so a /inspect/tool call with no
// session id has nothing to record; a recorder held anyway (aliasPending)
// turns the trusted dispatch memo off for every dispatch of the call and
// slows it for no verdict. A call with a session id keeps its recorder, and
// both answer the same verdict (the benign twin: the session does not move
// an ordinary command's cell).
//
// The recorder exists only on trains that carry the alias memo; where the
// request type has no aliasPending field there is nothing to scope and the
// test skips.
func TestGAP2075InspectRouteHoldsAnAliasRecorderOnlyForSessionCalls(t *testing.T) {
	if _, ok := reflect.TypeOf(trustedActionRequest{}).FieldByName("aliasPending"); !ok {
		t.Skip("this build has no cross-call alias recorder")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	cwd := filepath.Join(home, "proj")
	prev := trustedDispatchRunHook
	t.Cleanup(func() { trustedDispatchRunHook = prev })
	api := gap0437Server(t, gap0437Packs[0], "openclaw", "action")
	api.inspectToolScanTimeout = 60e9
	const command = "cat README.md | grep x; cat README.md | grep x"
	judge := func(session string) (judged, withRecorder int, action any) {
		trustedDispatchRunHook = func(request trustedActionRequest) {
			judged++
			if !reflect.ValueOf(request).FieldByName("aliasPending").IsNil() {
				withRecorder++
			}
		}
		defer func() { trustedDispatchRunHook = prev }()
		body := map[string]any{
			"tool": "exec", "connector": "openclaw", "args": map[string]any{"command": command, "workdir": cwd},
		}
		if session != "" {
			body["session_id"] = session
		}
		out := gap0437Serve(t, api.handleInspectTool, "/api/v1/inspect/tool", body)
		return judged, withRecorder, out["action"]
	}
	plainJudged, plainRecorders, plainAction := judge("")
	if plainJudged == 0 {
		t.Fatal("no dispatch was judged for the call with no session")
	}
	if plainRecorders != 0 {
		t.Errorf("a call with no session id held an alias recorder in %d of %d dispatches, want 0 (the memo is bypassed for nothing)", plainRecorders, plainJudged)
	}
	sessionJudged, sessionRecorders, sessionAction := judge("gap2075-session")
	if sessionJudged == 0 || sessionRecorders == 0 {
		t.Errorf("a call with a session id held no alias recorder (%d of %d dispatches); the cross-call alias raise needs it", sessionRecorders, sessionJudged)
	}
	if plainAction != sessionAction {
		t.Errorf("verdict with a session %v, without %v; the recorder must not move an ordinary command's cell", sessionAction, plainAction)
	}
}
