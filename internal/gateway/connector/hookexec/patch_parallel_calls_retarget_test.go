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

// GAP-0488, GAP-0073: parallel patch calls arrive as one Copilot envelope.
// The hook attests every target of it complete and reads each of them again
// after the gateway answered, so a target of any call that leads to the keys
// file by then is refused whatever the gateway said. The same envelope left
// alone runs.
func TestParallelPatchCallsRetargetedAfterTheAnswerAreRefused(t *testing.T) {
	for _, tc := range []struct {
		name     string
		retarget bool
		which    string
	}{
		{"first call retargeted", true, "target.txt"},
		{"second call retargeted", true, "other.txt"},
		{"nothing retargeted", false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var project, keys string
			sawCompleteProof := false
			rt := &stubRT{}
			rt.onRequest = func(_ *stubRT, req *http.Request) (*http.Response, error) {
				proof, ok := hookpaths.Decode(req.Header.Get(hookpaths.Header))
				first, second := filepath.Join(project, "target.txt"), filepath.Join(project, "other.txt")
				sawCompleteProof = ok && proof[hookpaths.PatchCompleteKey] == "1" && proof[first] == first && proof[second] == second
				if tc.retarget {
					victim := filepath.Join(project, tc.which)
					if err := os.Remove(victim); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(keys, victim); err != nil {
						t.Fatal(err)
					}
				}
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"action":"allow"}`)), Header: make(http.Header)}, nil
			}
			result := run(t, "copilot", rt, func(opts *Options) {
				t.Setenv("HOME", opts.Home)
				project = filepath.Join(opts.Home, "project")
				keys = filepath.Join(opts.Home, ".ssh", "authorized_keys")
				for _, dir := range []string{project, filepath.Dir(keys)} {
					if err := os.MkdirAll(dir, 0o700); err != nil {
						t.Fatal(err)
					}
				}
				for _, path := range []string{keys, filepath.Join(project, "target.txt"), filepath.Join(project, "other.txt")} {
					if err := os.WriteFile(path, []byte("x\n"), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				patch := func(name string) string {
					return "*** Begin Patch\n*** Update File: " + filepath.Join(project, name) + "\n@@\n x\n+y\n*** End Patch\n"
				}
				body, err := json.Marshal(map[string]any{
					"cwd": project,
					"toolCalls": []any{
						map[string]any{"id": "call_a", "name": "apply_patch", "args": patch("target.txt")},
						map[string]any{"id": "call_b", "name": "apply_patch", "args": patch("other.txt")},
					},
				})
				if err != nil {
					t.Fatal(err)
				}
				opts.Event = "preToolUse"
				opts.FailMode = "closed"
				opts.ManagedEnterprise = true
				opts.Stdin = strings.NewReader(string(body))
			})
			if !sawCompleteProof {
				t.Fatal("the hook did not attest both patch targets to the gateway")
			}
			blocked := g622bBlocked(result.code, result.stdout)
			if tc.retarget && !blocked {
				t.Fatalf("a retargeted patch received an allow: code=%d stdout=%q", result.code, result.stdout)
			}
			if !tc.retarget && blocked {
				t.Fatalf("an untouched parallel patch was refused: code=%d stdout=%q", result.code, result.stdout)
			}
		})
	}
}
