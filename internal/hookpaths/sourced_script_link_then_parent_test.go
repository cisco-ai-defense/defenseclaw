// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestClientDecisionReadsTheScriptBehindALinkBeforeTheParent: a name that
// passes a folder link and then .. opens the parent of the folder the link
// leads to, as the shell does (link/../wk.sh), not the parent of the link. The
// client reads the file the system opens: the ordinary script beside the
// linked folder is allowed although a writer lies at the lexical spelling in
// the project, and the writer behind the link is blocked although an ordinary
// script lies at the lexical spelling (rel-1-0-9:GAP-1038).
func TestClientDecisionReadsTheScriptBehindALinkBeforeTheParent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the Windows API resolves .. before it follows a link")
	}
	_, home, project := r106KeysHome(t)
	writer := "echo marker >> $HOME/.ssh/authorized_keys\n"
	ordinary := "echo ordinary >> report.txt\n"
	linked := filepath.Join(home, "chain", "live")
	if err := os.MkdirAll(linked, 0o700); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		filepath.Join(home, "chain", "wk.sh"):   writer,
		filepath.Join(home, "chain", "ok.sh"):   ordinary,
		filepath.Join(project, "wk.sh"):         ordinary,
		filepath.Join(project, "ok.sh"):         writer,
		filepath.Join(linked, "inside.sh"):      ordinary,
		filepath.Join(project, "plain", "x.sh"): ordinary,
	}
	if err := os.MkdirAll(filepath.Join(project, "plain"), 0o700); err != nil {
		t.Fatal(err)
	}
	for file, body := range files {
		if err := os.WriteFile(file, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(linked, filepath.Join(project, "portal")); err != nil {
		t.Skipf("link unavailable: %v", err)
	}
	t.Setenv("HOME", home)
	for _, command := range []string{". %s", "source %s", "bash %s", "sh %s", `bash -c ". %s"`, `sh -c "bash %s"`} {
		// portal/../wk.sh is home/chain/wk.sh (the writer), portal/../ok.sh
		// is home/chain/ok.sh (ordinary); plain/../wk.sh is project/wk.sh.
		for _, row := range []struct {
			name  string
			block bool
		}{
			{"portal/../wk.sh", true},
			{"portal/../ok.sh", false},
			{"plain/../wk.sh", false},
			{"plain/../ok.sh", true},
			{"portal/inside.sh", false},
		} {
			line := fmt.Sprintf(command, row.name)
			payload, err := json.Marshal(map[string]any{"session_id": "c1013", "hook_event_name": "PreToolUse",
				"cwd": project, "tool_name": "Bash", "tool_input": map[string]any{"command": line}})
			if err != nil {
				t.Fatal(err)
			}
			targets, ok := Decode(Resolve(payload))
			if !ok {
				t.Fatalf("%q: client header does not decode", line)
			}
			if got := targets[ActionDecisionKey] == ProtectedTargetDecision; got != row.block {
				t.Errorf("%q: client decision = %t, want %t", line, got, row.block)
			}
		}
	}
}
