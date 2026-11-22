// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

func crashedActors() map[string]any {
	return map[string]any{"actors": []map[string]any{
		{"atespace": "eng-web", "name": "fix-tests-1", "uid": "u1", "profile": "eng", "connector": "claudecode",
			"created_at": time.Now().Add(-5 * time.Minute), "state": "crashed", "unattended": true},
	}}
}

// GAP-0410: status shows a crashed agent as crashed with the way back.
func TestGAP0410StatusShowsACrash(t *testing.T) {
	useFakeAdmin(t, &fakeAdmin{h: map[string]func(http.ResponseWriter, *http.Request){"GET actors": jsonReply(crashedActors())}})
	out, _, err := runSubstrate(t, newSubstrateStatusCmd(), "fix-tests-1")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "crashed") || !strings.Contains(out, "defenseclaw substrate undo fix-tests-1") {
		t.Fatalf("status of a crashed agent:\n%s", out)
	}
	if strings.Contains(out, "Come back: defenseclaw substrate connect") {
		t.Fatalf("status sends the person to connect to a crashed agent:\n%s", out)
	}
}

// GAP-0410, GAP-0420: connect, logs and pull of a crashed agent say it
// crashed and how to get it back, instead of "the cluster is full" or a
// hang.
func TestGAP0410CommandsOnACrashedAgentSaySo(t *testing.T) {
	useFakeAdmin(t, &fakeAdmin{h: map[string]func(http.ResponseWriter, *http.Request){"GET actors": jsonReply(crashedActors())}})
	for name, run := range map[string]func() error{
		"connect": func() error { _, _, err := runSubstrate(t, newSubstrateConnectCmd(), "fix-tests-1"); return err },
		"logs":    func() error { _, _, err := runSubstrate(t, newSubstrateLogsCmd(), "fix-tests-1"); return err },
		"pull":    func() error { _, _, err := runSubstrate(t, newSubstratePullCmd(), "fix-tests-1"); return err },
	} {
		err := run()
		if err == nil || !strings.Contains(err.Error(), "crashed") || !strings.Contains(err.Error(), "defenseclaw substrate undo fix-tests-1") {
			t.Errorf("%s of a crashed agent: %v", name, err)
		}
	}
}

// GAP-0410: undo of a crashed agent asks the gateway to bring it back first
// (before, it ran the restore in the crashed actor and failed with a raw
// 503 AssignWorker prerequisite).
func TestGAP0410UndoRecoversACrashedAgent(t *testing.T) {
	f := &fakeAdmin{h: map[string]func(http.ResponseWriter, *http.Request){
		"GET actors": jsonReply(crashedActors()),
		"POST actors/eng-web/fix-tests-1/recover": jsonReply(map[string]any{"atespace": "eng-web", "name": "fix-tests-1", "state": "running"}),
	}}
	useFakeAdmin(t, f)
	_, errOut, _ := runSubstrate(t, newSubstrateUndoCmd(), "fix-tests-1", "--yes")
	recovered := false
	f.mu.Lock()
	for _, c := range f.calls {
		recovered = recovered || strings.HasPrefix(c, "POST actors/eng-web/fix-tests-1/recover")
	}
	f.mu.Unlock()
	if !recovered || !strings.Contains(errOut, "back at its last snapshot") {
		t.Fatalf("undo did not bring the crashed agent back (calls %v, stderr %q)", f.calls, errOut)
	}
}
