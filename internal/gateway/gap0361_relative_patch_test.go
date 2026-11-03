// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"os"
	"strings"
	"testing"
)

func TestGAP0361ManagedCodexKeepsVerifiedReportedProject(t *testing.T) {
	f := newAbsolutePatchFixture(t)
	// The caller can use the project while the managed gateway cannot stat it.
	resolve := resolveHookCWD
	resolveHookCWD = func(cwd string) (string, error) {
		if cwd == f.project {
			return "", os.ErrPermission
		}
		return resolve(cwd)
	}
	t.Cleanup(func() { resolveHookCWD = resolve })

	for _, profile := range []string{"default", "strict"} {
		for _, row := range []struct{ target, rule, defaultAction string }{
			{"../.zshrc", "persistence.shell_profile_write", "alert"},
			{"../.bash_history", "PATH-HISTORY", "alert"},
			{"src/main.go", "", "allow"},
		} {
			t.Run(profile+"/"+row.target, func(t *testing.T) {
				got, out := postApplyPatch(t, f, "codex", profile, true, updatePatch(row.target))
				want := row.defaultAction
				if profile == "strict" && row.rule != "" {
					want = "block"
				}
				if got != want || (row.rule != "" && !strings.Contains(out, row.rule)) {
					t.Fatalf("decision %s, want %s and %s: %.600s", got, want, row.rule, out)
				}
			})
		}
	}
}
