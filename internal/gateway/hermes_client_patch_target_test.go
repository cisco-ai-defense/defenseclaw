// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// The file a hook-listed Hermes patch target leads to is proved with the
// target, so the second path the link resolver adds for an ordinary link is
// not walked again behind ProtectHome. A file the hook did not name, a
// strict-tier link and an incomplete attestation are not proved.
func TestHermesClientPatchTargetProvesTheFileBehindAListedTarget(t *testing.T) {
	const cwd = "/home/u/proj"
	complete := func(extra map[string]string) map[string]string {
		targets := map[string]string{
			hookpaths.CWDKey:           cwd,
			hookpaths.PatchCompleteKey: "1",
			cwd + "/link.txt":          cwd + "/notes.txt",
			cwd + "/plain.txt":         cwd + "/plain.txt",
		}
		for key, value := range extra {
			targets[key] = value
		}
		return targets
	}
	managed := trustedActionRequest{ProtectedHomeHook: true}
	strict := trustedActionRequest{ProtectedHomeHook: true, strictPatchLinks: true}
	for _, tc := range []struct {
		name    string
		request trustedActionRequest
		targets map[string]string
		target  string
		want    bool
	}{
		{"listed link", managed, complete(nil), cwd + "/link.txt", true},
		{"file behind a listed link", managed, complete(nil), cwd + "/notes.txt", true},
		{"listed plain file", managed, complete(nil), cwd + "/plain.txt", true},
		{"file the hook did not name", managed, complete(nil), cwd + "/other.txt", false},
		{"key file the hook did not name", managed, complete(nil), "/home/u/.ssh/authorized_keys", false},
		{"strict: listed link", strict, complete(nil), cwd + "/link.txt", false},
		{"strict: file behind a listed link", strict, complete(nil), cwd + "/notes.txt", false},
		{"strict: listed plain file", strict, complete(nil), cwd + "/plain.txt", true},
		{"incomplete attestation", managed, complete(map[string]string{hookpaths.PatchCompleteKey: ""}), cwd + "/notes.txt", false},
		{"truncated attestation", managed, complete(map[string]string{hookpaths.TruncatedKey: "1"}), cwd + "/notes.txt", false},
		{"unproven write", managed, complete(map[string]string{hookpaths.UnprovenReasonKey: "x"}), cwd + "/notes.txt", false},
		{"not a managed hook", trustedActionRequest{}, complete(nil), cwd + "/notes.txt", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := hermesClientPatchTarget(tc.request, tc.targets, cwd, tc.target); got != tc.want {
				t.Fatalf("hermesClientPatchTarget = %v, want %v", got, tc.want)
			}
		})
	}
}
