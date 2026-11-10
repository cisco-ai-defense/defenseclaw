// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// The rows create POSIX links in a temporary home.

//go:build !windows

package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// TestStepUpOrdinaryFileInAShellFunctionIsAllowedInBalanced: a here-document
// patch inside a shell function reaches the same physical file as the same
// patch at the top level. For a name that steps up a directory and whose
// lexical clean reads as a sudoers drop-in, the file is an ordinary file of the
// user, on the per-user and on the managed gateway, whether the function is
// called or not (a body no call runs writes nothing in the balanced tiers).
func TestStepUpOrdinaryFileInAShellFunctionIsAllowedInBalanced(t *testing.T) {
	const grant = "reviewer ALL=(ALL) NOPASSWD: ALL\n"
	for _, managed := range []bool{false, true} {
		for _, called := range []bool{false, true} {
			name := map[bool]string{false: "per-user", true: "managed"}[managed] + "/" +
				map[bool]string{false: "uncalled", true: "called"}[called]
			t.Run(name, func(t *testing.T) {
				blocked, body := postConnectorHookBehindProtectHome(t, "codex", managed, "default",
					func(home, project string) map[string]any {
						spelling := stepUpDeepOrdinaryName(t, project, "etc/sudoers.d/review")
						physical, ok := hookpaths.ResolvePatchWriteTarget(project + "/" + spelling)
						if !ok || !strings.HasPrefix(physical, home+"/") {
							t.Fatalf("physical = %q, known = %t", physical, ok)
						}
						if err := os.MkdirAll(filepath.Dir(physical), 0o700); err != nil {
							t.Fatal(err)
						}
						command := "f() {\n" + codexHeredocPatch("Add File", spelling, "+"+grant) + "}\n"
						if called {
							command += "f\n"
						} else {
							command += "true\n"
						}
						return codexBashCall(command)(project)
					})
				if blocked {
					t.Fatalf("an ordinary file is blocked: %.500s", body)
				}
			})
		}
	}
}

// TestStepUpKeyFileInACalledShellFunctionIsBlockedInEveryProfile is the twin of
// the test above: the same function, called, with a header that steps up out
// of a link to the SSH folder reaches the authorized-keys file and blocks in
// every profile, on the per-user and on the managed gateway.
func TestStepUpKeyFileInACalledShellFunctionIsBlockedInEveryProfile(t *testing.T) {
	for _, managed := range []bool{false, true} {
		for _, profile := range []string{"default", "permissive", "strict"} {
			name := map[bool]string{false: "per-user", true: "managed"}[managed] + "/" + profile
			t.Run(name, func(t *testing.T) {
				blocked, body := postConnectorHookBehindProtectHome(t, "codex", managed, profile,
					func(home, project string) map[string]any {
						folder := filepath.Join(home, ".ssh", "keys")
						if err := os.MkdirAll(folder, 0o700); err != nil {
							t.Fatal(err)
						}
						stepUpLink(t, project, "lnk-keys", folder)
						spelling := "lnk-keys/../authorized_keys"
						physical, ok := hookpaths.ResolvePatchWriteTarget(project + "/" + spelling)
						if !ok || physical != filepath.Join(home, ".ssh", "authorized_keys") {
							t.Fatalf("physical = %q, known = %t", physical, ok)
						}
						command := "f() {\n" + codexHeredocPatch("Add File", spelling, "+ssh-ed25519 AAAAC3review review\n") + "}\nf\n"
						return codexBashCall(command)(project)
					})
				if !blocked {
					t.Fatalf("the key file is not blocked")
				}
				if !strings.Contains(body, authorizedKeysRuleID) {
					t.Fatalf("block lacks the key-file rule: %.500s", body)
				}
			})
		}
	}
}
