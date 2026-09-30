// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterprisepolicy

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func TestPublishVerifyRemoveAll(t *testing.T) {
	withHigherSources(t)
	opts := testOptions(t)
	opts = withPolicy(opts, "copilot", func(p *config.EnterpriseConnectorPolicy) { p.Ownership = "off" })
	connectors := []string{"cursor", "Codex", "claudecode", "copilot", "devin", "openclaw", "kiro"}
	result, err := Publish(opts, connectors)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"claudecode", "codex", "cursor"}; !reflect.DeepEqual(result.MachinePolicyConnectors, want) {
		t.Fatalf("machine policy connectors = %v, want %v", result.MachinePolicyConnectors, want)
	}
	routes := map[string]string{}
	for _, state := range result.States {
		routes[state.Connector] = state.Route
	}
	if routes["devin"] != RoutePerUser || routes["openclaw"] != RouteUnsupported || routes["kiro"] != RoutePerUser || routes["copilot"] != RouteUnsupported {
		t.Fatalf("routes: %v", routes)
	}
	if !result.Complete() {
		t.Fatalf("publish should be complete: %+v", result.States)
	}
	summary, err := ParsePublicPolicy([]byte(readFile(t, opts.PublicPolicyPath)))
	if err != nil || !summary.Connectors["devin"].Guard || summary.Connectors["codex"].Guard {
		t.Fatalf("public summary: %v %+v", err, summary)
	}
	verify, err := VerifyAll(opts, connectors)
	if err != nil || !verify.Complete() {
		t.Fatalf("verify: %v %+v", err, verify.States)
	}
	if again, err := Publish(opts, connectors); err != nil || again.Changed {
		t.Fatalf("second publish must be a no-op: %v", err)
	}
	if _, err := RemoveAll(opts); err != nil {
		t.Fatal(err)
	}
	for _, rel := range []string{"etc/codex/requirements.toml", "etc/claude-code/managed-settings.d/90-defenseclaw.json", "etc/cursor/hooks.json", "etc/defenseclaw/machine-policy.json"} {
		if _, err := os.Stat(filepath.Join(opts.Root, rel)); !os.IsNotExist(err) {
			t.Errorf("%s must be removed: %v", rel, err)
		}
	}
	for _, rel := range []string{"etc/codex", "etc/cursor", "etc/claude-code/managed-settings.d"} {
		if _, err := os.Stat(filepath.Join(opts.Root, rel)); !os.IsNotExist(err) {
			t.Errorf("directory %s created by DefenseClaw must be removed when empty: %v", rel, err)
		}
	}
}

// Kiro's route must say what the guardian does with it. The Linux and macOS
// guardians enroll Kiro per user (the hook goes into each user's global
// ~/.kiro/hooks), so reporting ACP there told administrators Kiro was
// protected only through the ACP guard. The Windows guardian refuses Kiro,
// so it stays on ACP there.
func TestKiroRouteFollowsItsEnrollment(t *testing.T) {
	for goos, want := range map[string]string{
		"linux":   RoutePerUser,
		"darwin":  RoutePerUser,
		"windows": RouteACP,
	} {
		if got := RouteFor("kiro", goos); got != want {
			t.Errorf("RouteFor(kiro, %s) = %q, want %q", goos, got, want)
		}
	}
}

func TestTrustChecksRejectWritableAncestors(t *testing.T) {
	opts := testOptions(t)
	opts.SkipTrustChecks = false
	previous := trustedOwner
	uid := uint32(os.Getuid())
	trustedOwner = func(owner uint32) bool { return owner == uid }
	t.Cleanup(func() { trustedOwner = previous })
	if err := os.Chmod(opts.Root, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := (codexTarget{}).Reconcile(opts); err != nil {
		t.Fatalf("trusted tree must be writable: %v", err)
	}
	etc := filepath.Join(opts.Root, "etc")
	if err := os.Chmod(etc, 0o777); err != nil {
		t.Fatal(err)
	}
	syscall.Umask(0o022)
	_, err := codexTarget{}.Reconcile(opts)
	if err == nil || !strings.Contains(err.Error(), "group/other-writable") {
		t.Fatalf("a world-writable ancestor must be refused, got %v", err)
	}
}

// Disabling a connector or setting ownership: off removes DefenseClaw's
// earlier entries on the next publish instead of leaving them (and the
// managed-hooks-only lock) until uninstall.
func TestPublishRetiresConnectorsNoLongerPublished(t *testing.T) {
	withHigherSources(t)
	opts := testOptions(t)
	codexFile := codexPath(t, opts)
	writeFile(t, codexFile, adminCodexRequirements)
	if _, err := Publish(opts, []string{"codex", "claudecode", "cursor"}); err != nil {
		t.Fatal(err)
	}
	if !fileExists(claudeFloorFile(t, opts)) {
		t.Fatal("publish must write the Claude Code version floor")
	}

	off := withPolicy(opts, "codex", func(p *config.EnterpriseConnectorPolicy) { p.Ownership = "off" })
	result, err := Publish(off, []string{"codex", "claudecode", "cursor"})
	if err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, codexFile); got != adminCodexRequirements {
		t.Fatalf("ownership: off must restore the administrator requirements:\n%s", got)
	}
	if len(result.Retired) != 1 || result.Retired[0].Connector != "codex" || !result.Changed {
		t.Fatalf("retired = %+v", result.Retired)
	}
	if !result.Complete() {
		t.Fatalf("a retired connector must not make the publish incomplete: %+v", result.States)
	}

	result, err = Publish(off, []string{"codex", "cursor"})
	if err != nil {
		t.Fatal(err)
	}
	mustNotExist(t, claudeDropIn(t, opts), "the drop-in of a disabled connector")
	if recorded, _ := ClaudeVersionFloorRecorded(opts); recorded || fileExists(claudeFloorFile(t, opts)) {
		t.Fatal("disabling claudecode must withdraw the version floor and its record")
	}
	if len(result.Retired) != 1 || result.Retired[0].Connector != "claudecode" {
		t.Fatalf("retired = %+v", result.Retired)
	}

	verify := withPolicy(off, "cursor", func(p *config.EnterpriseConnectorPolicy) { p.Ownership = "verify_only" })
	result, err = Publish(verify, []string{"codex", "cursor"})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Retired) != 0 || !strings.Contains(readFile(t, cursorHooksPath(t, opts)), testHookBinary) {
		t.Fatalf("verify_only keeps DefenseClaw's entries (it still verifies them): %+v", result.Retired)
	}
	if again, err := Publish(verify, []string{"codex", "cursor"}); err != nil || len(again.Retired) != 0 || again.Changed {
		t.Fatalf("retirement must be a one-time change: %+v %v", again, err)
	}
}
