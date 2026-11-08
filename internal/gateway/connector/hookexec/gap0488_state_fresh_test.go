// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// GAP-0488, GAP-0073 (g622b round 8): a native patch target is judged by the
// identity of the file against the whole active state, read fresh, through
// the proof and the answer. These cells pin the cases a cached or bounded
// view of the state let through. POSIX permissions emulate the managed
// gateway that cannot read the project.

//go:build !windows

package hookexec

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// The proof itself indexes state because swap.txt is an ordinary project
// hard link. A policy file appears during the gateway answer, and swap.txt
// is changed to a hard link to it. The final hook reread must refuse it.
func TestG622b8NewProtectedStateAfterProofIsRefused(t *testing.T) {
	for _, tc := range g622bPatchCalls {
		t.Run(tc.name, func(t *testing.T) {
			home, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			t.Setenv("HOME", home)
			project := filepath.Join(home, "proj")
			state := filepath.Join(home, ".defenseclaw", "policies", "new-rule.rego")
			if err := os.MkdirAll(project, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Dir(state), 0700); err != nil {
				t.Fatal(err)
			}
			source, target := filepath.Join(project, "ordinary.txt"), filepath.Join(project, "swap.txt")
			if err := os.WriteFile(source, []byte("x\n"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Link(source, target); err != nil {
				t.Fatal(err)
			}
			rt := &stubRT{}
			sawProof := false
			rt.onRequest = func(_ *stubRT, req *http.Request) (*http.Response, error) {
				proof, ok := hookpaths.Decode(req.Header.Get(hookpaths.Header))
				sawProof = ok && proof[hookpaths.PatchCompleteKey] == "1" && proof[target] == target
				if err := os.WriteFile(state, []byte("x\n"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(target); err != nil {
					t.Fatal(err)
				}
				if err := os.Link(state, target); err != nil {
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
				t.Fatal("hook did not attest the ordinary hard-linked target")
			}
			if !g622bBlocked(result.code, result.stdout) {
				t.Errorf("protected state hard link created during gateway answer was allowed: code=%d stdout=%q", result.code, result.stdout)
			}
		})
	}
}
