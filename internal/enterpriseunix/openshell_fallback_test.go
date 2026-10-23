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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

// The Linux docker fallback (owner decision 2026-10-10): driver vm or auto
// with driver_fallback docker renders the fallback's gateway configuration,
// checks the fallback's own prerequisites in rows of their own, reports a
// MicroVM prerequisite the host lacks as openshell_driver_fallback (users
// still get docker sandboxes), and records both readinesses for the gateway.
// driver_fallback: none renders no fallback and keeps the refusal warning.
func TestSandboxDockerFallbackLifecycle(t *testing.T) {
	packaged := func(t *testing.T) *osHost {
		h := newOSHost(t, "linux")
		for _, p := range []string{"/usr/bin/openshell", "/usr/bin/openshell-gateway", "/usr/bin/docker", "/usr/sbin/mke2fs"} {
			if err := os.MkdirAll(filepath.Dir(h.env.P(p)), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(h.env.P(p), []byte("x"), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		h.runner.replies = map[string]fakeReply{"rpm -q --qf %{VERSION} openshell": {result: CommandResult{Stdout: []byte("0.1.5")}}}
		return h
	}
	record := func(t *testing.T, h *osHost) openshell.PrerequisitesRecord {
		var rec openshell.PrerequisitesRecord
		if err := json.Unmarshal([]byte(h.read(h.env.prerequisitesPath())), &rec); err != nil {
			t.Fatal(err)
		}
		return rec
	}

	for _, driver := range []string{"vm", "auto"} {
		t.Run(driver+" falls back to docker", func(t *testing.T) {
			h := packaged(t)
			r := h.ensure(sandboxConfig(t, "linux", true, map[string]any{"install": "prerequisite", "driver": driver}))
			requireOK(t, r)
			if toml := h.read(h.env.renderedTOMLPath()); !strings.Contains(toml, "compute_driver = 'vm'") {
				t.Errorf("gateway.toml:\n%s", toml)
			}
			fb := h.read(h.env.renderedFallbackTOMLPath())
			for _, want := range []string{"compute_driver = 'docker'", "bind_address = '127.0.0.1:17670'"} {
				if !strings.Contains(fb, want) {
					t.Errorf("%s lacks %q:\n%s", openshell.GatewayFallbackTOMLFile, want, fb)
				}
			}
			if h.mode(h.env.renderedFallbackTOMLPath()) != 0o644 {
				t.Error("the fallback configuration is not 0644")
			}
			if state, _ := rowState(r, "sandbox openshell"); !strings.Contains(state, "driver="+driver+" fallback=docker") {
				t.Errorf("openshell row = %q", state)
			}
			if state, ok := rowState(r, "sandbox fallback docker"); !ok || !strings.HasPrefix(state, "ok:") {
				t.Errorf("fallback docker row = %q %t", state, ok)
			}
			if !hasWarning(r, codeDriverFallback) || hasWarning(r, codeOpenShellPrerequisite) {
				t.Errorf("warnings = %+v", r.Warnings)
			}
			rec := record(t, h)
			if rec.Driver != driver || rec.Ready || rec.Fallback == nil || !rec.Fallback.Ready || rec.Fallback.Driver != "docker" {
				t.Errorf("prerequisites.json = %+v (fallback %+v)", rec, rec.Fallback)
			}
		})
	}

	t.Run("driver_fallback none refuses instead", func(t *testing.T) {
		h := packaged(t)
		r := h.ensure(sandboxConfig(t, "linux", true, map[string]any{"install": "prerequisite", "driver": "vm", "driver_fallback": "none"}))
		requireOK(t, r)
		if h.exists(h.env.renderedFallbackTOMLPath()) {
			t.Error("a fallback configuration under driver_fallback: none")
		}
		if state, _ := rowState(r, "sandbox openshell"); !strings.Contains(state, "driver=vm fallback=none") {
			t.Errorf("openshell row = %q", state)
		}
		if _, ok := rowState(r, "sandbox fallback docker"); ok || hasWarning(r, codeDriverFallback) || !hasWarning(r, codeOpenShellPrerequisite) {
			t.Errorf("rows/warnings = %+v %+v", r.Services, r.Warnings)
		}
		if rec := record(t, h); rec.Fallback != nil {
			t.Errorf("record has a fallback: %+v", rec.Fallback)
		}
		// Back to the default: the fallback file appears; then docker: it goes.
		requireOK(t, h.ensure(sandboxConfig(t, "linux", true, map[string]any{"install": "prerequisite", "driver": "vm"})))
		if !h.exists(h.env.renderedFallbackTOMLPath()) {
			t.Error("no fallback configuration after driver_fallback went back to docker")
		}
		r = h.ensure(sandboxConfig(t, "linux", true, map[string]any{"install": "prerequisite", "driver": "docker"}))
		requireOK(t, r)
		if h.exists(h.env.renderedFallbackTOMLPath()) {
			t.Error("the docker driver keeps a fallback configuration")
		}
		if state, _ := rowState(r, "sandbox openshell"); strings.Contains(state, "fallback=") {
			t.Errorf("the docker driver names a fallback: %q", state)
		}
	})
}
