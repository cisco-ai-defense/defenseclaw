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

package enterpriseunix

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

// writeExecutables creates executable stand-ins at the canonical paths.
func (h *osHost) writeExecutables(t *testing.T, paths ...string) {
	t.Helper()
	for _, p := range paths {
		if err := os.MkdirAll(filepath.Dir(h.env.P(p)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(h.env.P(p), []byte("x"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
}

// GAP-0189: a Mac's prerequisite rows skip an OpenShell another account can
// change (Homebrew symlinks of the account that ran brew) for the root-owned
// one, and fail when that is the only one; the rendered driver_dir never
// names it.
func TestSandboxPrerequisiteSkipsUntrustedBinaries(t *testing.T) {
	h := newOSHost(t, "darwin")
	h.writeExecutables(t, "/opt/homebrew/bin/openshell", "/opt/homebrew/bin/openshell-gateway", "/opt/homebrew/libexec/openshell/openshell-driver-vm")
	h.env.Trust = func(path string, kind TrustKind) error {
		if strings.Contains(path, "/opt/homebrew/") {
			return errors.New("symlinks are not allowed in managed file path")
		}
		return nil
	}
	cfg := sandboxConfig(t, "darwin", true, map[string]any{"install": "prerequisite", "version": "0.1.5"})
	r := h.ensure(cfg)
	requireOK(t, r)
	for _, row := range []string{"sandbox openshell cli", "sandbox openshell gateway", "sandbox microvm driver"} {
		if state, _ := rowState(r, row); !strings.HasPrefix(state, "missing:") || !strings.Contains(state, "an account other than root can change") {
			t.Errorf("%s = %q, want missing (untrusted)", row, state)
		}
	}
	if toml := h.read(h.env.renderedTOMLPath()); strings.Contains(toml, "/opt/homebrew") {
		t.Errorf("gateway.toml names another account's Homebrew:\n%s", toml)
	}

	h.writeExecutables(t, "/usr/local/bin/openshell", "/usr/local/bin/openshell-gateway", "/usr/local/libexec/openshell/openshell-driver-vm")
	h.runner.replies = map[string]fakeReply{
		"openshell --version":           {result: CommandResult{Stdout: []byte("openshell 0.1.5\n")}},
		"openshell-gateway --version":   {result: CommandResult{Stdout: []byte("openshell-gateway 0.1.5\n")}},
		"openshell-driver-vm --version": {result: CommandResult{Stdout: []byte("openshell-driver-vm 0.1.5\n")}},
	}
	r = h.ensure(cfg)
	requireOK(t, r)
	for row, want := range map[string]string{
		"sandbox openshell cli":     "ok: 0.1.5 (/usr/local/bin/openshell)",
		"sandbox openshell gateway": "ok: 0.1.5 (/usr/local/bin/openshell-gateway)",
		"sandbox microvm driver":    "ok: 0.1.5 (/usr/local/libexec/openshell/openshell-driver-vm)",
		"sandbox openshell release": "ok: openshell, openshell-gateway, openshell-driver-vm are all 0.1.5",
	} {
		if state, _ := rowState(r, row); !strings.HasPrefix(state, want) {
			t.Errorf("%s = %q, want %q", row, state, want)
		}
	}
	if toml := h.read(h.env.renderedTOMLPath()); !strings.Contains(toml, "/usr/local/libexec/openshell") {
		t.Errorf("gateway.toml does not name the root-owned driver:\n%s", toml)
	}
}

// GAP-0245, GAP-0277: every part of the administrator's OpenShell is held
// to the pin, and parts of different releases fail: the 0.1.1 gateway of
// the rpm cannot run NVIDIA's 0.1.5 MicroVM driver.
func TestSandboxPrerequisiteVersions(t *testing.T) {
	t.Run("a pin the root-owned release does not meet", func(t *testing.T) {
		h := newOSHost(t, "darwin")
		h.writeExecutables(t, "/usr/local/bin/openshell", "/usr/local/bin/openshell-gateway", "/usr/local/libexec/openshell/openshell-driver-vm")
		h.runner.replies = map[string]fakeReply{
			"openshell --version":           {result: CommandResult{Stdout: []byte("openshell 0.1.5\n")}},
			"openshell-gateway --version":   {result: CommandResult{Stdout: []byte("openshell-gateway 0.1.5\n")}},
			"openshell-driver-vm --version": {result: CommandResult{Stdout: []byte("openshell-driver-vm 0.1.5\n")}},
		}
		r := h.ensure(sandboxConfig(t, "darwin", true, map[string]any{"install": "prerequisite", "version": "0.1.4"}))
		requireOK(t, r)
		for _, row := range []string{"sandbox openshell cli", "sandbox openshell gateway", "sandbox microvm driver"} {
			if state, _ := rowState(r, row); !strings.HasPrefix(state, "missing:") || !strings.Contains(state, "0.1.5 is installed, enterprise.openshell.version pins 0.1.4") {
				t.Errorf("%s = %q, want the pin mismatch", row, state)
			}
		}
		requireRefusedReleases(t, h, "0.1.5", "openshell cli", "openshell gateway", "microvm driver")
	})
	// GAP-0266: an installed release below SupportedMin is recorded with
	// its version, so the gateway says it is installed and unsupported.
	t.Run("an installed release older than the floor", func(t *testing.T) {
		h := newOSHost(t, "linux")
		h.writeExecutables(t, "/usr/bin/openshell", "/usr/bin/openshell-gateway", "/usr/libexec/openshell/openshell-driver-vm", "/usr/sbin/mke2fs")
		h.runner.replies = map[string]fakeReply{
			"rpm -q --qf %{VERSION} openshell":         {result: CommandResult{Stdout: []byte("0.1.3")}},
			"rpm -q --qf %{VERSION} openshell-gateway": {result: CommandResult{Stdout: []byte("0.1.3")}},
			"openshell-driver-vm --version":            {result: CommandResult{Stdout: []byte("openshell-driver-vm 0.1.3\n")}},
		}
		r := h.ensure(sandboxConfig(t, "linux", true, map[string]any{"install": "prerequisite", "driver": "vm"}))
		requireOK(t, r)
		requireRefusedReleases(t, h, "0.1.3", "openshell cli", "openshell gateway", "microvm driver")
	})
	t.Run("parts of different releases", func(t *testing.T) {
		h := newOSHost(t, "linux")
		h.writeExecutables(t, "/usr/bin/openshell", "/usr/bin/openshell-gateway", "/usr/libexec/openshell/openshell-driver-vm", "/usr/sbin/mke2fs")
		h.runner.replies = map[string]fakeReply{
			"rpm -q --qf %{VERSION} openshell":         {result: CommandResult{Stdout: []byte("0.1.1")}},
			"rpm -q --qf %{VERSION} openshell-gateway": {result: CommandResult{Stdout: []byte("0.1.1")}},
			"openshell-driver-vm --version":            {result: CommandResult{Stdout: []byte("openshell-driver-vm 0.1.5\n")}},
		}
		r := h.ensure(sandboxConfig(t, "linux", true, map[string]any{"install": "prerequisite", "driver": "vm"}))
		requireOK(t, r)
		state, _ := rowState(r, "sandbox openshell release")
		if !strings.HasPrefix(state, "missing:") || !strings.Contains(state, "openshell 0.1.1, openshell-gateway 0.1.1, openshell-driver-vm 0.1.5 are not one release") {
			t.Errorf("release row = %q", state)
		}
		var record openshell.PrerequisitesRecord
		if err := json.Unmarshal([]byte(h.read(h.env.prerequisitesPath())), &record); err != nil || record.Ready {
			t.Errorf("prerequisites.json = %+v %v, want not ready", record, err)
		}
	})
}

// requireRefusedReleases checks that the published prerequisites.json
// names release for each of items, the OpenShell parts whose release the
// lifecycle refused (GAP-0266).
func requireRefusedReleases(t *testing.T, h *osHost, release string, items ...string) {
	t.Helper()
	var record struct {
		Ready   bool `json:"ready"`
		Missing []struct {
			Item    string `json:"item"`
			Version string `json:"version"`
		} `json:"missing"`
	}
	if err := json.Unmarshal([]byte(h.read(h.env.prerequisitesPath())), &record); err != nil || record.Ready {
		t.Fatalf("prerequisites.json = %+v %v, want not ready", record, err)
	}
	got := map[string]string{}
	for _, m := range record.Missing {
		got[m.Item] = m.Version
	}
	for _, item := range items {
		if got[item] != release {
			t.Errorf("prerequisites.json %s version = %q, want %q (missing %+v)", item, got[item], release, record.Missing)
		}
	}
}

// GAP-0472: the gateway runs only in DefenseClaw's own unit, whose shim sets
// umask 0022, so a UMask=0077 drop-in for NVIDIA's unused
// openshell-gateway.service is no reason to say MicroVMs cannot run.
func TestSandboxIgnoresTheUnusedNVIDIAUnitUmask(t *testing.T) {
	h := newOSHost(t, "linux")
	for p, data := range map[string]string{
		"/usr/lib/systemd/user/openshell-gateway.service":          "[Service]\nExecStart=/usr/bin/openshell-gateway\nUMask=0077\n",
		"/etc/systemd/user/openshell-gateway.service.d/umask.conf": "[Service]\nUMask=0077\n",
	} {
		if err := os.MkdirAll(filepath.Dir(h.env.P(p)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(h.env.P(p), []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	r := h.ensure(sandboxConfig(t, "linux", true, map[string]any{"install": "prerequisite", "driver": "vm"}))
	requireOK(t, r)
	if state, ok := rowState(r, "sandbox gateway umask"); ok {
		t.Errorf("a umask row for the unused NVIDIA unit: %q", state)
	}
	if strings.Contains(fmt.Sprint(r.Warnings), "umask") {
		t.Errorf("warnings name the NVIDIA unit's umask: %+v", r.Warnings)
	}
}

// GAP-0244: a prerequisite-mode pin change is no per-account switch, and a
// switch skips, silently, an account that never used sandboxes; nothing is
// created in any home.
func TestSandboxSwitchLeavesUnusedAccountsAlone(t *testing.T) {
	h := newOSHost(t, "darwin")
	bob := SandboxAccount{Name: "bob", UID: h.alice.UID + 1, GID: h.alice.GID, Home: "/Users/bob"}
	if err := os.MkdirAll(h.env.P(bob.Home), 0o755); err != nil {
		t.Fatal(err)
	}
	h.ops.accounts = append(h.ops.accounts, bob)
	state := filepath.Join(h.alice.Home, h.env.daemonStateRel())
	if err := os.MkdirAll(h.env.P(state), 0o700); err != nil {
		t.Fatal(err)
	}
	requireOK(t, h.ensure(sandboxConfig(t, "darwin", true, map[string]any{"install": "prerequisite", "version": "0.1.5"})))

	r := h.ensure(sandboxConfig(t, "darwin", true, map[string]any{"install": "prerequisite", "version": "0.1.4"}))
	requireOK(t, r)
	if len(h.ops.stopped()) != 0 || containsLine(r.Changes, "switched the sandbox setup") || len(h.env.loadOpenShellState().Pending) != 0 {
		t.Fatalf("a prerequisite pin change switched accounts: stops %v, changes %v", h.ops.stopped(), r.Changes)
	}

	r = h.ensure(sandboxConfig(t, "darwin", true, map[string]any{"install": "prerequisite", "version": "0.1.4", "gateway_port": 17693}))
	requireOK(t, r)
	if !containsLine(r.Changes, "switched the sandbox setup of alice") || strings.Contains(strings.Join(r.Changes, "\n"), "of bob") {
		t.Errorf("changes = %v", r.Changes)
	}
	if hasWarning(r, codeSandboxUserState) {
		t.Errorf("warnings = %+v", r.Warnings)
	}
	if entries, _ := os.ReadDir(h.env.P(bob.Home)); len(entries) != 0 {
		t.Errorf("the switch created %v in bob's home", entries)
	}
}
