// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"strings"
	"testing"
)

type coworkMissingACLRunner struct {
	Runner
	missing string
}

func (r coworkMissingACLRunner) Run(ctx context.Context, name string, args ...string) (CommandResult, error) {
	if name == "ls" {
		kept := make([]string, 0, len(args))
		for _, arg := range args {
			if arg != r.missing {
				kept = append(kept, arg)
			}
		}
		args = kept
	}
	return r.Runner.Run(ctx, name, args...)
}

func TestCoworkMacACLReadDenialAndRepair(t *testing.T) {
	h := newTestHost(t, "darwin")
	h.env.GOARCH = "arm64"
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	c := coworkTestConfig(t, h, "on", true)
	coworkTestProfile(t, h, c, macCoworkPreferences, nil)
	requireOK(t, h.run(Options{Action: ActionEnsure}))
	archive := macCoworkDir + "/defenseclaw-cowork-arm64.tar.gz"
	files := []string{archive, archive + ".sig", archive + ".args"}
	h.runner.acls = map[string][]string{h.env.P(macCoworkDir): {
		"group:everyone deny search", "user:administrator allow readattr",
	}}
	for _, path := range files {
		h.runner.acls[h.env.P(path)] = []string{"group:everyone deny read", "user:administrator allow readattr"}
	}
	if problems := h.env.coworkACLProblems(t.Context(), files); !strings.Contains(strings.Join(problems, "; "), "deny read") {
		t.Fatalf("host-delivery ACL check missed read denial: %v", problems)
	}
	if status := h.run(Options{Action: ActionStatus}); !strings.Contains(messagesOf(status.Errors, codeVerify), "deny read") {
		t.Fatalf("generic status missed Cowork read denial: %+v", status.Errors)
	}
	requireOK(t, h.run(Options{Action: ActionRepair}))
	for _, path := range append(files, macCoworkDir) {
		if got := h.runner.acls[h.env.P(path)]; len(got) != 1 || got[0] != "user:administrator allow readattr" {
			t.Fatalf("repair changed unrelated ACL or kept denial on %s: %v", path, got)
		}
	}
	if problems := h.env.coworkACLProblems(t.Context(), files); len(problems) != 0 {
		t.Fatalf("repaired Cowork ACLs not ready: %v", problems)
	}
	h.env.Runner = coworkMissingACLRunner{Runner: h.env.Runner, missing: h.env.P(archive)}
	if problems := h.env.coworkACLProblems(t.Context(), files); !strings.Contains(strings.Join(problems, "; "), "did not list") {
		t.Fatalf("unread file ACL did not fail closed: %v", problems)
	}
}

func TestCoworkMacSharedAncestorACLIsOnlyReported(t *testing.T) {
	h := newTestHost(t, "darwin")
	h.env.GOARCH = "arm64"
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	c := coworkTestConfig(t, h, "on", true)
	coworkTestProfile(t, h, c, macCoworkPreferences, nil)
	requireOK(t, h.run(Options{Action: ActionEnsure}))
	archive := macCoworkDir + "/defenseclaw-cowork-arm64.tar.gz"
	ancestor := h.env.P("/Library/Application Support")
	h.runner.acls = map[string][]string{ancestor: {"group:everyone deny search"}}
	if problems := h.env.coworkACLProblems(t.Context(), []string{archive}); !strings.Contains(strings.Join(problems, "; "), "system folders") {
		t.Fatalf("shared ancestor denial was not actionable: %v", problems)
	}
	if repair := h.run(Options{Action: ActionRepair}); repair.OK {
		t.Fatal("repair accepted inaccessible shared ancestor")
	}
	if len(h.runner.acls[ancestor]) != 1 {
		t.Fatal("repair changed the shared ancestor ACL")
	}
}

func TestCoworkMacACLHasNoTargetsWhenOff(t *testing.T) {
	h := newTestHost(t, "darwin")
	if targets := h.env.coworkACLTargets(nil); len(targets) != 0 {
		t.Fatalf("disabled feature has ACL targets: %v", targets)
	}
	if problems := h.env.coworkACLProblems(t.Context(), nil); len(problems) != 0 || len(h.runner.calls) != 0 {
		t.Fatalf("disabled feature probed ACLs: %v, %v", problems, h.runner.calls)
	}
}
