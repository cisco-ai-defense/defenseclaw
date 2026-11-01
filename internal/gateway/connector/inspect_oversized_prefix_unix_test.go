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

//go:build !windows

package connector

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// GAP-1512: a per-user generic inspect hook whose input is over the 1 MiB
// cap, with the connector's saved open mode, submits the cap's prefix for a
// bounded review. The request must fit the gateway's own 1 MiB body cap:
// the raw prefix wrapped as one JSON string did not (a 1 MiB prefix alone is
// at the cap, and escaping grows it), so the gateway answered 413 and the
// hook refused the call. The gateway's verdict on the bounded request
// decides: allow runs the call, block stops it.
func TestGenericInspectOversizedPrefixFitsTheGatewayCap(t *testing.T) {
	if _, err := exec.LookPath("jq"); err != nil {
		t.Skip("jq is required")
	}
	// Quotes and backslashes double when encoded: the worst ordinary case.
	oversized := `{"command":"` + strings.Repeat(`x"\`, (1<<20)/3+4096) + `"}`
	for _, tc := range []struct {
		script, verdict string
		wantAllow       bool
	}{
		{"inspect-tool.sh", `{"action":"allow"}`, true},
		{"inspect-tool-response.sh", `{"action":"allow"}`, true},
		{"inspect-tool.sh", `{"action":"block","reason":"protected target"}`, false},
	} {
		t.Run(tc.script+"/"+tc.verdict, func(t *testing.T) {
			var mu sync.Mutex
			var got []byte
			refused := false
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
				mu.Lock()
				defer mu.Unlock()
				if err != nil {
					refused = true
					http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
					return
				}
				got = body
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, tc.verdict)
			}))
			defer server.Close()
			data := t.TempDir()
			hookDir := filepath.Join(data, "hooks")
			opts := SetupOpts{DataDir: data, APIAddr: strings.TrimPrefix(server.URL, "http://"), APIToken: "scoped-test-token", HookFailMode: "open"}
			if err := WriteHookScriptsForConnectorObjectWithOpts(hookDir, opts, NewCodexConnector()); err != nil {
				t.Fatal(err)
			}
			installNativeGatewayForHookTest(t, data, hookDir)
			cmd := exec.Command("bash", filepath.Join(hookDir, tc.script))
			cmd.Stdin = strings.NewReader(oversized)
			cmd.Env = append(sanitizedTestEnv(), "HOME="+data, "DEFENSECLAW_HOME="+data, "TOOL_NAME=Bash", "DEFENSECLAW_GATEWAY_AUTOSTART=0")
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			err := cmd.Run()
			mu.Lock()
			defer mu.Unlock()
			if refused {
				t.Fatalf("the gateway refused the bounded review as over its cap; stderr=%s", stderr.String())
			}
			// An 8 KiB head (GAP-1841): a larger prefix runs past the generic
			// endpoint's 200 ms scan budget and gets 504 with no verdict.
			if len(got) == 0 || len(got) > 64*1024 || !bytes.Contains(got, []byte(`"bounded_prefix_review":true`)) ||
				!bytes.Contains(got, []byte(`"content_truncated":true`)) {
				t.Fatalf("bounded review request: %d bytes, markers=%v; stderr=%s", len(got),
					bytes.Contains(got, []byte(`"bounded_prefix_review":true`)), stderr.String())
			}
			if allowed := err == nil; allowed != tc.wantAllow {
				t.Fatalf("allowed=%v want %v (err=%v) stderr=%s", allowed, tc.wantAllow, err, stderr.String())
			}
		})
	}
}
