// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookexec

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

type g622bPatchCall struct {
	name, connector, event, allow string
	args                          func(patch string) map[string]any
}

var g622bPatchCalls = []g622bPatchCall{
	{"hermes v4a patch", "hermes", "pre_tool_call", `{"action":"allow"}`,
		func(p string) map[string]any { return map[string]any{"mode": "patch", "patch": p} }},
	{"opencode native patch", "opencode", "tool.execute.before",
		`{"action":"allow","mode":"action","hook_output":{"decision":"allow"}}`,
		func(p string) map[string]any { return map[string]any{"patchText": p} }},
}

func (c g622bPatchCall) payload(t *testing.T, project string) string {
	t.Helper()
	patch := "*** Begin Patch\n*** Update File: swap.txt\n@@\n x\n+y\n*** End Patch\n"
	raw, err := json.Marshal(map[string]any{"hook_event_name": c.event, "tool_name": "patch", "tool_input": c.args(patch), "cwd": project})
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// g622bSwaps are the ways an ordinary target becomes a protected file after
// the hook read it: a hard link, a symlink, and a hard link put in place by a
// rename (the way an editor saves).
var g622bSwaps = []struct {
	name string
	make func(protected, target string) error
}{
	{"hard link", func(protected, target string) error { return os.Link(protected, target) }},
	{"symlink", func(protected, target string) error { return os.Symlink(protected, target) }},
	{"hard link renamed into place", func(protected, target string) error {
		staged := target + ".new"
		if err := os.Link(protected, staged); err != nil {
			return err
		}
		return os.Rename(staged, target)
	}},
}

func g622bBlocked(code int, stdout string) bool {
	return code != 0 || strings.Contains(stdout, "block") || strings.Contains(stdout, "deny")
}

// GAP-0488, GAP-0073: whatever file the hook attested as an ordinary patch
// target, if it is a file of the active DefenseClaw state (or an
// authorized-keys file) by the time the gateway has answered, the hook
// refuses the call: for a hard link, a symlink and a rename-swapped hard
// link, for Hermes V4A and the OpenCode patch.
func TestG622bProtectedFileSwappedInAfterTheGatewayProofIsRefused(t *testing.T) {
	for _, tc := range g622bPatchCalls {
		for _, protected := range []string{".defenseclaw/config.yaml", ".defenseclaw/policies/rule.rego", ".ssh/authorized_keys"} {
			for _, swap := range g622bSwaps {
				t.Run(tc.name+" "+protected+" "+swap.name, func(t *testing.T) {
					home, err := filepath.EvalSymlinks(t.TempDir())
					if err != nil {
						t.Fatal(err)
					}
					t.Setenv("HOME", home)
					project := filepath.Join(home, "proj")
					file := filepath.Join(home, filepath.FromSlash(protected))
					target := filepath.Join(project, "swap.txt")
					for _, dir := range []string{project, filepath.Dir(file)} {
						if err := os.MkdirAll(dir, 0o700); err != nil {
							t.Fatal(err)
						}
					}
					for _, path := range []string{file, target} {
						if err := os.WriteFile(path, []byte("x\n"), 0o600); err != nil {
							t.Fatal(err)
						}
					}
					rt := &stubRT{}
					sawProof := false
					rt.onRequest = func(_ *stubRT, req *http.Request) (*http.Response, error) {
						proof, ok := hookpaths.Decode(req.Header.Get(hookpaths.Header))
						sawProof = ok && proof[hookpaths.PatchCompleteKey] == "1" && proof[target] == target
						if err := os.Remove(target); err != nil {
							t.Fatal(err)
						}
						if err := swap.make(file, target); err != nil {
							t.Fatal(err)
						}
						return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(tc.allow)), Header: make(http.Header)}, nil
					}
					result := run(t, tc.connector, rt, func(o *Options) {
						o.Event = tc.event
						o.FailMode = "closed"
						o.ManagedEnterprise = true
						o.Stdin = strings.NewReader(tc.payload(t, project))
					})
					if !sawProof {
						t.Fatal("the hook did not attest an ordinary target")
					}
					if !g622bBlocked(result.code, result.stdout) {
						t.Errorf("the protected file received an allow: code=%d stdout=%q", result.code, result.stdout)
					}
				})
			}
		}
	}
}

// writeSwapper makes the target a protected file in the Write that carries
// the answer to the agent, as a swap that lands while the answer is written.
type g622bWriteSwapper struct {
	bytes.Buffer
	swap func() error
	err  error
	saw  bool
}

func (w *g622bWriteSwapper) Write(p []byte) (int, error) {
	if !w.saw {
		w.saw = true
		w.err = w.swap()
	}
	if w.err != nil {
		return 0, w.err
	}
	return w.Buffer.Write(p)
}

// GAP-0488, GAP-0073: the answer is written and the agent reads it only when
// the hook exits, so a target that becomes a protected file while the allow
// is written is revoked by the hook (a failure exit), not delivered as an
// allow. The twin: a target saved again as the same ordinary file while the
// answer is written keeps its allow.
func TestG622bProtectedFileSwappedInWhileTheAllowIsWrittenIsRevoked(t *testing.T) {
	tc := g622bPatchCalls[1] // Hermes writes no bytes for an allow
	for _, protected := range []string{".defenseclaw/config.yaml", ".ssh/authorized_keys"} {
		for _, swap := range append(g622bSwaps, struct {
			name string
			make func(protected, target string) error
		}{"ordinary atomic save", nil}) {
			t.Run(protected+" "+swap.name, func(t *testing.T) {
				home, err := filepath.EvalSymlinks(t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				t.Setenv("HOME", home)
				project := filepath.Join(home, "proj")
				file := filepath.Join(home, filepath.FromSlash(protected))
				target := filepath.Join(project, "swap.txt")
				for _, dir := range []string{project, filepath.Dir(file)} {
					if err := os.MkdirAll(dir, 0o700); err != nil {
						t.Fatal(err)
					}
				}
				for _, path := range []string{file, target} {
					if err := os.WriteFile(path, []byte("x\n"), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				writer := &g622bWriteSwapper{}
				writer.swap = func() error {
					if err := os.Remove(target); err != nil {
						return err
					}
					if swap.make == nil {
						return os.WriteFile(target, []byte("x\n"), 0o600)
					}
					return swap.make(file, target)
				}
				rt := &stubRT{}
				rt.onRequest = func(_ *stubRT, req *http.Request) (*http.Response, error) {
					return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(tc.allow)), Header: make(http.Header)}, nil
				}
				result := run(t, tc.connector, rt, func(o *Options) {
					o.Event = tc.event
					o.FailMode = "closed"
					o.ManagedEnterprise = true
					o.Stdin = strings.NewReader(tc.payload(t, project))
					o.Stdout = writer
				})
				if !writer.saw || writer.err != nil {
					t.Fatalf("answer_write=%t swap_error=%v", writer.saw, writer.err)
				}
				if swap.make == nil {
					if result.code != 0 || !strings.Contains(writer.String(), `"decision":"allow"`) {
						t.Errorf("ordinary target saved while the answer is written was refused: code=%d answer=%q", result.code, writer.String())
					}
					return
				}
				if result.code == 0 {
					t.Errorf("the protected file kept its allow: code=%d answer=%q", result.code, writer.String())
				}
			})
		}
	}
}
