// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// The source disappears only for the gateway side of the proof, as it does
// behind ProtectHome. The hook header was built while the user could see it.
func TestManagedHookCopySourceFactsWithInvisibleGatewayPath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX managed service")
	}
	root := t.TempDir()
	home, project := filepath.Join(root, "home"), filepath.Join(root, "home", "proj")
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	if err := os.MkdirAll(filepath.Dir(keys), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(project, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keys, []byte("marker\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Chdir(project)
	for _, connector := range []string{"claudecode", "codex"} {
		for _, row := range []struct {
			name, command       string
			link, header, block bool
		}{
			{"archive symlink", "cp --archive disklink notes3.txt && echo k >> notes3.txt", true, true, true},
			{"short archive symlink", "cp -a disklink notes4.txt && echo k >> notes4.txt", true, true, true},
			{"older client symlink", "cp -a disklink notes4.txt && echo k >> notes4.txt", true, false, true},
			{"archive regular", "cp -a regular.txt notes5.txt && echo k >> notes5.txt", false, true, false},
		} {
			t.Run(connector+"/"+row.name, func(t *testing.T) {
				source := filepath.Join(project, "regular.txt")
				if row.link {
					source = filepath.Join(project, "disklink")
				}
				if row.link {
					if err := os.Symlink(keys, source); err != nil {
						t.Fatal(err)
					}
				} else if err := os.WriteFile(source, []byte("ordinary\n"), 0600); err != nil {
					t.Fatal(err)
				}
				body := mustJSON(t, map[string]any{"session_id": "marker-session", "hook_event_name": "PreToolUse",
					"tool_name": "Bash", "cwd": project, "tool_input": map[string]any{"command": row.command, "description": "d"}})
				header := hookpaths.Resolve(body)
				targets, ok := hookpaths.Decode(header)
				if !ok {
					t.Fatal("client header did not decode")
				}
				wantFact := "0"
				if row.link {
					wantFact = "1"
				}
				if got := targets[hookpaths.SourceLinkFactPrefix+source]; got != wantFact {
					t.Fatalf("source fact = %q, want %q", got, wantFact)
				}
				if err := os.Remove(source); err != nil {
					t.Fatal(err)
				}
				cfg := &config.Config{}
				cfg.Guardrail.Mode = "action"
				cfg.Guardrail.Connector = connector
				api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
				req := httptest.NewRequest(http.MethodPost, "/api/v1/hook", strings.NewReader(string(body)))
				if row.header {
					req.Header.Set(hookpaths.Header, header)
				}
				if connector == "codex" {
					setTestCodexHookBinding(req, "PreToolUse", defaultTestCodexHookContract)
				}
				req = req.WithContext(withManagedHookPeer(req.Context(), managedHookPeer{Home: home}))
				recorder := httptest.NewRecorder()
				api.handleAgentHook(connector).ServeHTTP(recorder, req)
				want := `{"action":"allow"`
				if row.block {
					want = `{"action":"block"`
				}
				if !strings.HasPrefix(recorder.Body.String(), want) {
					t.Fatalf("response = %s, want %s", recorder.Body.String(), want)
				}
			})
		}
	}
}
