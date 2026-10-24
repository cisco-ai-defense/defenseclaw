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

	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

// Every docker configuration the lifecycle renders keeps the managed
// gateways' Docker objects in a sandbox namespace of their own, so a managed
// account's gateway start no longer removes the supervisors of the sandboxes
// another account's own gateway runs in OpenShell's default namespace
// (GAP-0566): the docker driver's gateway.toml, and the docker fallback of the
// MicroVM driver. The MicroVM render itself makes no Docker objects.
func TestRenderedDockerConfigurationsUseTheManagedNamespace(t *testing.T) {
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
	label := "sandbox_label = '" + openshell.ManagedDockerNamespace + "'"

	t.Run("docker driver", func(t *testing.T) {
		h := packaged(t)
		requireOK(t, h.ensure(sandboxConfig(t, "linux", true, map[string]any{"install": "prerequisite", "driver": "docker", "gateway_port": 17671})))
		toml := h.read(h.env.renderedTOMLPath())
		if !strings.Contains(toml, "compute_driver = 'docker'") || !strings.Contains(toml, label) {
			t.Errorf("gateway.toml lacks %q:\n%s", label, toml)
		}
		if strings.Contains(toml, "sandbox_label = '"+openshell.DefaultDockerNamespace+"'") {
			t.Errorf("gateway.toml names the default namespace:\n%s", toml)
		}
	})
	t.Run("docker fallback of the MicroVM driver", func(t *testing.T) {
		h := packaged(t)
		requireOK(t, h.ensure(sandboxConfig(t, "linux", true, map[string]any{"install": "prerequisite", "driver": "vm"})))
		if fb := h.read(h.env.renderedFallbackTOMLPath()); !strings.Contains(fb, label) {
			t.Errorf("%s lacks %q:\n%s", openshell.GatewayFallbackTOMLFile, label, fb)
		}
		if toml := h.read(h.env.renderedTOMLPath()); strings.Contains(toml, "sandbox_label") {
			t.Errorf("the MicroVM gateway.toml names a docker namespace:\n%s", toml)
		}
	})
}
