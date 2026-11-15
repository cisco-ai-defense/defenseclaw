// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// On Windows a glob copy out of an SSH folder the walk cannot tie to the
// active home (another account, a nested .ssh under the profile) keeps the
// block of rel in every tier of the tool-inspect route; the glob placeholder
// of GAP-0018 had left it with no reading at all (rel-1-0-10:GAP-0944).
func TestGAP0944SSHFolderGlobCopyKeepsTheRelBlockOnWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("rel blocks these rows on Windows only; POSIX rows are pinned by TestOwnSSHFolderCopyThroughTheHookRoute")
	}
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	for _, dir := range []string{".ssh", "project", "backup"} {
		if err := os.MkdirAll(filepath.Join(home, dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(home, ".ssh", "authorized_keys"), []byte("marker\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	replacer := strings.NewReplacer("{H}", home)
	for _, command := range []string{
		`cp -r {H}/.ssh/* /tmp/ssh_backup/`,
		`cp -r {H}/backup/* {H}/.ssh/`,
		`cp -r C:\Users\gap0944other\.ssh\* /tmp/ssh_backup/`,
		`cp -r C:/Users/gap0944other/.ssh/* /tmp/ssh_backup/`,
	} {
		for _, p := range gap0437Packs {
			a := gap0437Server(t, p, "openclaw", "action")
			out := gap0944Inspect(t, a, cwd, replacer.Replace(command))
			if out["action"] != "block" {
				t.Errorf("%s %s: action %v findings %v, want block (rel)", p.name, command, out["action"], out["findings"])
			}
		}
	}
}

// gap0944Inspect is gap0437Inspect that asks again after a scan timeout: the
// first call of a fresh server on a cold Windows runner can spend the inspect
// budget compiling the rule set (rel-1-0-10:GAP-0958), which says nothing
// about the verdict these rows pin.
func gap0944Inspect(t *testing.T, a *APIServer, cwd, command string) map[string]any {
	t.Helper()
	raw, _ := json.Marshal(map[string]any{
		"tool": "exec", "connector": "openclaw", "args": map[string]any{"command": command, "workdir": cwd},
	})
	for try := 0; try < 3; try++ {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/inspect/tool", bytes.NewReader(raw))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		a.handleInspectTool(w, req)
		if w.Code == http.StatusGatewayTimeout {
			continue
		}
		if w.Code != http.StatusOK {
			t.Fatalf("status %d body %s", w.Code, w.Body.String())
		}
		var out map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	t.Fatalf("%s: three scan timeouts", command)
	return nil
}
