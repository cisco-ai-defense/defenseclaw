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
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// runPreremove runs packaging/linux/preremove.sh for a package removal
// ("remove") with a gateway that prints result as `uninstall --json` does
// and exits 1. It returns the script's exit code, its stderr and the state
// directory the script keeps a failed result in.
func runPreremove(t *testing.T, result *enterprisestatus.Result) (int, string, string) {
	t.Helper()
	script, err := os.ReadFile(filepath.Join("..", "..", "packaging", "linux", "preremove.sh"))
	if err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()
	document, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	resultPath := filepath.Join(work, "result.json")
	if err := os.WriteFile(resultPath, document, 0o600); err != nil {
		t.Fatal(err)
	}
	gateway := filepath.Join(work, "gateway")
	if err := os.WriteFile(gateway, []byte("#!/bin/sh\ncat '"+resultPath+"'\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	systemd, state := filepath.Join(work, "systemd"), filepath.Join(work, "state")
	if err := os.Mkdir(systemd, 0o755); err != nil {
		t.Fatal(err)
	}
	text := strings.NewReplacer(
		"/opt/defenseclaw/bin/defenseclaw-gateway", gateway,
		"/var/lib/defenseclaw-enterprise", state,
		"/run/systemd/system", systemd,
	).Replace(string(script))
	cmd := exec.Command("sh", "-c", text, "preremove.sh", "remove")
	cmd.Env = append(os.Environ(), "TMPDIR="+work)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	err = cmd.Run()
	var exitErr *exec.ExitError
	switch {
	case err == nil:
		return 0, stderr.String(), state
	case errors.As(err, &exitErr):
		return exitErr.ExitCode(), stderr.String(), state
	default:
		t.Fatal(err)
	}
	return 0, "", ""
}

// GAP-1519: an uninstall that stopped before removing the binaries, because
// vendor machine policy (or per-user hooks) still named them, failed with
// uninstall_failed, which preremove.sh let through: dnf or apt then deleted
// the binaries those registrations call, after the uninstall had started the
// services again. The stop has its own code, uninstall_incomplete, and the
// package removal keeps its files on it, as on the precheck refusal, and on
// nothing else.
func TestPackageRemovalKeepsTheFilesWhenTheUninstallKeptTheBinaries(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh")
	}
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	fail := true
	h.env.MachinePolicy = failingRemovePolicy{MachinePolicyManager: h.env.MachinePolicy, fail: &fail}
	kept := h.run(Options{Action: ActionUninstall})
	requireError(t, kept, codeUninstallIncomplete)
	if !exists(h.env.P(filepath.Join(h.env.Layout.BinDir, binHook))) {
		t.Fatal("the uninstall removed the hook binary the machine policy still names")
	}
	rc, stderr, state := runPreremove(t, kept)
	if rc != 1 || !strings.Contains(stderr, "package files were kept") || !strings.Contains(stderr, "retry the removal") {
		t.Fatalf("preremove exit %d after an uninstall that kept the binaries, want 1 with the next step; stderr:\n%s", rc, stderr)
	}
	if data, err := os.ReadFile(filepath.Join(state, "last-package-result.json")); err != nil || !strings.Contains(string(data), `"uninstall_incomplete"`) {
		t.Fatalf("preremove did not keep the uninstall result for the administrator (%v)", err)
	}

	refused := &enterprisestatus.Result{}
	refused.AddError(codeUninstallPrecheck, "nothing was changed")
	refused.Finish("linux", 0)
	if rc, stderr, _ := runPreremove(t, refused); rc != 1 || !strings.Contains(stderr, "precheck refused") {
		t.Fatalf("preremove exit %d after the precheck refusal, want 1; stderr:\n%s", rc, stderr)
	}

	// Any other failure leaves the package removal to go on, also when a
	// message merely mentions the code: only the exact code keeps the files.
	other := &enterprisestatus.Result{}
	other.AddError(codeUninstall, "remove /etc/defenseclaw/x: permission denied (not uninstall_incomplete)")
	other.AddError(codeUninstallIncomplete+"_x", "a longer code")
	other.Finish("linux", 0)
	if rc, stderr, _ := runPreremove(t, other); rc != 0 || !strings.Contains(stderr, "uninstall reported a problem") {
		t.Fatalf("preremove exit %d after an uninstall_failed result, want 0; stderr:\n%s", rc, stderr)
	}
}

// GAP-1065: preinstall.sh read config_version only at column 0, so a config
// whose document is indented as a whole (valid YAML) passed the guard that
// refuses a package older than the config, and the package replaced every
// file before its ensure failed. It reads the top-level key at the
// document's own indentation, quoted or not, and not a nested key.
func TestPreinstallReadsTheTopLevelConfigVersion(t *testing.T) {
	if _, err := exec.LookPath("awk"); err != nil {
		t.Skip("no awk")
	}
	script, err := os.ReadFile(filepath.Join("..", "..", "packaging", "linux", "preinstall.sh"))
	if err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()
	cfg := filepath.Join(work, "config.yaml")
	text := strings.NewReplacer(
		"/etc/defenseclaw/config.yaml", cfg,
		"/var/lib/defenseclaw-enterprise", filepath.Join(work, "state"),
		"/run/systemd/system", filepath.Join(work, "no-systemd"),
	).Replace(string(script))
	newer := fmt.Sprint(config.MaxSupportedConfigVersion + 1)
	for content, refused := range map[string]bool{
		"config_version: " + newer + "\n":                                      true,
		"  config_version: " + newer + "\n  gateway:\n    port: 1\n":           true,
		"# managed\n---\n    \"config_version\": '" + newer + "' # pushed\n":   true,
		"config_version : \"" + newer + "\"\n":                                 true,
		"gateway:\n  config_version: " + newer + "\nconfig_version: 9\n":       false,
		"  gateway:\n    config_version: " + newer + "\n  config_version: 9\n": false,
		"config_version: 9\n": false,
	} {
		if err := os.WriteFile(cfg, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("sh", "-c", text, "preinstall.sh", "install")
		var stderr strings.Builder
		cmd.Stderr = &stderr
		err := cmd.Run()
		if got := err != nil; got != refused || refused && !strings.Contains(stderr.String(), "config_version "+newer) {
			t.Errorf("config %q: refused=%v (%v), want %v; stderr: %s", content, got, err, refused, stderr.String())
		}
	}
}
