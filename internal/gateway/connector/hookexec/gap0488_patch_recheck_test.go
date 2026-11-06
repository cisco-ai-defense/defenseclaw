// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookexec

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// GAP-0488, GAP-0073: behind ProtectHome the gateway takes a patch target
// from the evidence the managed hook read before the request, and cannot read
// it again. A target that is swapped for a link to the keys file after that
// reading, before the gateway answers, is refused by the hook whatever the
// gateway said. The same patch with the target unchanged runs.
func TestGAP0488PatchTargetSwappedAfterReadingIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name, connector, event, allow string
		body                          func(patch string) map[string]any
	}{
		{
			name: "hermes v4a patch", connector: "hermes", event: "pre_tool_call", allow: `{"action":"allow"}`,
			body: func(patch string) map[string]any {
				return map[string]any{"hook_event_name": "pre_tool_call", "tool_name": "patch",
					"tool_input": map[string]any{"mode": "patch", "patch": patch}}
			},
		},
		{
			name: "opencode native patch", connector: "opencode", event: "tool.execute.before",
			allow: `{"action":"allow","mode":"action","hook_output":{"decision":"allow"}}`,
			body: func(patch string) map[string]any {
				return map[string]any{"hook_event_name": "tool.execute.before", "tool_name": "patch",
					"tool_input": map[string]any{"patchText": patch}}
			},
		},
	} {
		for _, swap := range []bool{false, true} {
			name := tc.name + " unchanged target"
			if swap {
				name = tc.name + " target swapped for a link to the keys file"
			}
			t.Run(name, func(t *testing.T) {
				home, err := filepath.EvalSymlinks(t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				t.Setenv("HOME", home)
				project := filepath.Join(home, "proj")
				for _, dir := range []string{filepath.Join(home, ".ssh"), project} {
					if err := os.MkdirAll(dir, 0o700); err != nil {
						t.Fatal(err)
					}
				}
				keys := filepath.Join(home, ".ssh", "authorized_keys")
				target := filepath.Join(project, "swap.txt")
				for path, content := range map[string]string{keys: "k\n", target: "x\n"} {
					if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				patch := "*** Begin Patch\n*** Update File: swap.txt\n@@\n x\n+y\n*** End Patch\n"
				payload := tc.body(patch)
				payload["cwd"] = project
				stdin, err := json.Marshal(payload)
				if err != nil {
					t.Fatal(err)
				}
				rt := &stubRT{}
				sawEvidence := false
				rt.onRequest = func(s *stubRT, req *http.Request) (*http.Response, error) {
					targets, decoded := hookpaths.Decode(req.Header.Get(hookpaths.Header))
					sawEvidence = decoded && targets[hookpaths.PatchCompleteKey] == "1" && targets[target] == target
					if swap {
						if err := os.Remove(target); err != nil {
							t.Fatal(err)
						}
						if err := os.Symlink(keys, target); err != nil {
							t.Fatal(err)
						}
					}
					return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(tc.allow)), Header: make(http.Header)}, nil
				}
				result := run(t, tc.connector, rt, func(o *Options) {
					o.Event = tc.event
					o.FailMode = "closed"
					o.ManagedEnterprise = true
					o.Stdin = strings.NewReader(string(stdin))
				})
				if !sawEvidence {
					t.Fatal("the hook did not attest the patch target to the gateway")
				}
				blocked := strings.Contains(result.stdout, "block") || strings.Contains(result.stdout, "deny")
				if swap && !blocked {
					t.Fatalf("stdout = %q (code %d), want the swapped patch target refused", result.stdout, result.code)
				}
				if !swap && blocked {
					t.Fatalf("stdout = %q (code %d), want the unchanged patch to run", result.stdout, result.code)
				}
			})
		}
	}
}
