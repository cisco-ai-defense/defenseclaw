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
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The rpm and deb install the three sandbox user units under
// /usr/lib/systemd/user; the first run records their digests, and every later
// run found them in the previous deployment and absent from the new plan, took
// them for dropped files and unlinked them. Verify then failed on the missing
// units and rolled the run back, so no ensure, repair or apply after the first
// completed (GAP-0176, GAP-0177). They stay, also when the sandbox subsystem
// is turned off.
func TestPackageUserUnitsSurviveLaterEnsureRuns(t *testing.T) {
	h := newOSHost(t, "linux")
	stagePackage(t, h.testHost, "1.0.0")
	units := map[string]string{}
	for _, u := range h.env.userUnits() {
		path := h.env.userUnitPath(u, ChannelPackage)
		if !strings.HasPrefix(path, "/usr/lib/systemd/user/") {
			t.Fatalf("package unit path %q is outside %s", path, packageUserUnitDir)
		}
		data, err := h.env.userUnitBytes(u)
		if err != nil {
			t.Fatal(err)
		}
		units[path] = string(data)
		writeHostFile(t, h.testHost, path, units[path])
	}
	// The package installs the launcher and the directory of the rendered
	// gateway configuration as well.
	if err := os.MkdirAll(h.env.P(h.env.openshellDir()), 0o755); err != nil {
		t.Fatal(err)
	}
	launcher := h.env.P(h.env.launcherPath())
	if err := os.MkdirAll(filepath.Dir(launcher), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(h.env.launcherTarget(), launcher); err != nil {
		t.Fatal(err)
	}
	run := func(cfg []byte) {
		t.Helper()
		requireOK(t, h.run(Options{Action: ActionEnsure, FromPackage: true, Reason: "package", ConfigFile: writeTempConfig(t, cfg)}))
		for path, want := range units {
			if got := h.read(path); got != want {
				t.Fatalf("%s = %q after ensure, want the package's %q", path, got, want)
			}
		}
		if !h.exists(h.env.openshellDir()) {
			t.Fatalf("ensure removed the package's %s", h.env.openshellDir())
		}
	}
	on := sandboxConfig(t, "linux", true, map[string]any{"install": "prerequisite", "driver": "docker"})
	run(on)
	run(on)
	run(sandboxConfig(t, "linux", false, nil))
	run(on)
	// A package install with sandboxes off from the start (the package
	// default) keeps the directory too.
	run(sandboxConfig(t, "linux", false, nil))
}
