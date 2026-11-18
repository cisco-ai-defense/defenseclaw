// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/api"
)

// GAP-0410: after checkpoint saves a restore point in the agent, it has the
// cluster store a snapshot of the agent, so the restore point survives a
// crash of its worker. When the cluster cannot, the person is told the
// restore point is lost on a crash; a failed snapshot is an error.
func TestGAP0410CheckpointHasTheClusterStoreASnapshot(t *testing.T) {
	for name, tc := range map[string]struct {
		h       func(http.ResponseWriter, *http.Request)
		kept    bool
		note    string
		wantErr bool
	}{
		"stored":                 {h: jsonReply(map[string]any{"atespace": "eng-web", "name": "fix-tests-1", "state": "running", "snapshot_generation": 2}), kept: true},
		"stored, start pending":  {h: jsonReply(map[string]any{"atespace": "eng-web", "name": "fix-tests-1", "state": "suspended"}), kept: true, note: "defenseclaw substrate connect fix-tests-1"},
		"stored, no worker":      {h: jsonReply(map[string]any{"atespace": "eng-web", "name": "fix-tests-1", "state": "suspended", "resume_error": "no_worker"}), kept: true, note: "no free worker"},
		"gateway without route":  {kept: false, note: "lost if the agent's worker crashes"},
		"agent stopped meantime": {h: jsonStatus(http.StatusConflict, "not_running"), note: "lost if it crashes"},
		"snapshot failed":        {h: jsonStatus(http.StatusBadGateway, "snapshot_failed"), wantErr: true},
		"may be suspended":       {h: jsonStatus(http.StatusBadGateway, "snapshot_failed_may_be_suspended"), wantErr: true},
	} {
		t.Run(name, func(t *testing.T) {
			f := &fakeAdmin{h: map[string]func(http.ResponseWriter, *http.Request){}}
			if tc.h != nil {
				f.h["POST actors/eng-web/fix-tests-1/snapshot"] = tc.h
			}
			useFakeAdmin(t, f)
			s, err := substrateOpen(nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			kept, note, err := substrateKeepSnapshot(context.Background(), s, api.Actor{Atespace: "eng-web", Name: "fix-tests-1"}, "3")
			if kept != tc.kept || (err != nil) != tc.wantErr || !strings.Contains(note, tc.note) {
				t.Fatalf("kept %v note %q err %v", kept, note, err)
			}
			if tc.wantErr && (!strings.Contains(err.Error(), "restore point 3 is saved in the agent") || !errors.Is(err, errSubstrateNotKept) || (name == "may be suspended") != strings.Contains(err.Error(), "fix-tests-1 may be suspended now")) {
				t.Fatalf("error %v does not say the restore point itself is saved", err)
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if len(f.calls) != 1 || !strings.HasPrefix(f.calls[0], "POST actors/eng-web/fix-tests-1/snapshot") {
				t.Fatalf("calls %v", f.calls)
			}
		})
	}
}
