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
// reading, while the gateway answers or when its answer is closed, is refused
// by the hook whatever the gateway said. The same patch with the target
// unchanged, or saved again as the same ordinary file by an editor, runs.
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
		for _, tm := range []struct {
			name, when string
			swap       bool
		}{
			{" unchanged target", "", false},
			{" target saved again as the same ordinary file", "answer", false},
			{" target swapped for a link to the keys file", "answer", true},
			{" target swapped for a link to the keys file as the answer closes", "close", true},
			{" target saved again as the same ordinary file as the answer closes", "close", false},
		} {
			swap := tm.swap
			name := tc.name + tm.name
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
					change := func() {
						if tm.when == "" {
							return
						}
						if swap {
							if err := os.Remove(target); err != nil {
								t.Fatal(err)
							}
							if err := os.Symlink(keys, target); err != nil {
								t.Fatal(err)
							}
							return
						}
						// An editor save: the same ordinary path, written to a
						// new file and renamed over the old one.
						saved := target + ".tmp"
						if err := os.WriteFile(saved, []byte("x\n"), 0o600); err != nil {
							t.Fatal(err)
						}
						if err := os.Rename(saved, target); err != nil {
							t.Fatal(err)
						}
					}
					body := io.NopCloser(strings.NewReader(tc.allow))
					if tm.when == "close" {
						body = &closeHook{Reader: strings.NewReader(tc.allow), onClose: change}
					} else {
						change()
					}
					return &http.Response{StatusCode: 200, Body: body, Header: make(http.Header)}, nil
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

// closeHook runs a function when the response body is closed.
type closeHook struct {
	io.Reader
	onClose func()
	closed  bool
}

func (c *closeHook) Close() error {
	if !c.closed {
		c.closed = true
		c.onClose()
	}
	return nil
}
