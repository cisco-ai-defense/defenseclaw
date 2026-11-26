// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/api"
	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/workspace"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

// GAP-0476: substrate undo reports the files it reverted, as path digests,
// with its checkpoint; when the report fails or the leader has no mark for
// the checkpoint, the undo stands and the launcher says what the chain may
// still report.
func TestGAP0476UndoReportsTheRevertedFiles(t *testing.T) {
	commit := strings.Repeat("cd", 20)
	info := &workspace.UndoInfo{ID: "2", Commit: commit, Removed: []string{"/work/app/dl.sh"}, Restored: []string{"/work/app/run.sh"}}
	removed, _ := guardrail.ToolChainPOSIXPathDigest("/work/app/dl.sh")
	restored, _ := guardrail.ToolChainPOSIXPathDigest("/work/app/run.sh")
	for _, tc := range []struct {
		name  string
		reply func(http.ResponseWriter, *http.Request)
		note  string
	}{
		{"known", jsonReply(map[string]any{"forgotten": 2, "checkpoint_known": true}), ""},
		{"unknown mark", jsonReply(map[string]any{"forgotten": 2, "checkpoint_known": false}), "has no mark for restore point 2"},
		{"older gateway", jsonStatus(http.StatusNotFound, "not_found"), "the cluster was not told about this undo"},
		{"older leader", jsonStatus(http.StatusBadGateway, "chain_report_failed"), "the cluster was not told about this undo"},
	} {
		var sent api.WorkspaceEvent
		reply := tc.reply
		f := &fakeAdmin{h: map[string]func(http.ResponseWriter, *http.Request){
			"POST actors/eng-web/fix-tests-1/workspace-event": func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewDecoder(r.Body).Decode(&sent)
				reply(w, r)
			},
		}}
		useFakeAdmin(t, f)
		s, err := substrateOpen(nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		var stderr bytes.Buffer
		cmd := &cobra.Command{}
		cmd.SetErr(&stderr)
		substrateReportUndo(context.Background(), cmd, s.Client, api.Actor{Atespace: "eng-web", Name: "fix-tests-1"}, info)
		if sent.Event != "undo" || sent.Checkpoint != commit || len(sent.Removed) != 1 || sent.Removed[0] != removed ||
			len(sent.Restored) != 1 || sent.Restored[0] != restored {
			t.Fatalf("%s: sent %+v", tc.name, sent)
		}
		if got := stderr.String(); (tc.note == "") != (got == "") || !strings.Contains(got, tc.note) {
			t.Fatalf("%s: note %q, want %q", tc.name, got, tc.note)
		}
	}
}
