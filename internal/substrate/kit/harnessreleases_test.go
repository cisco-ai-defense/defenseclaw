// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package kit

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
)

// Lane K1: every release the kit builds into a base image is one the harness
// has reviewed digests for, has a hook contract, and renders settings.
func TestHarnessReleasesAreInstallableAndCovered(t *testing.T) {
	for name, version := range HarnessReleases {
		h, ok := harness.Get(name)
		if !ok {
			t.Errorf("%s: no harness", name)
			continue
		}
		steps, err := h.InstallSteps(version)
		if err != nil || len(steps) == 0 {
			t.Errorf("%s %s: install steps: %v", name, version, err)
			continue
		}
		if run := steps[0].Run; !strings.Contains(run, version) {
			t.Errorf("%s %s: the install step does not name the release", name, version)
		}
		res := connector.ResolveSandboxHookContract(name, version)
		if res.Status != connector.HookCompatibilityKnown {
			t.Errorf("%s %s: hook contract %+v", name, version, res)
			continue
		}
		if HarnessRelease(name) != version || AgentVersion(name, h.DefaultVersion) != version {
			t.Errorf("%s: AgentVersion", name)
		}
		if _, err := SubstrateArtifacts(h.Provider, version, DefaultConfig()); err != nil {
			t.Errorf("%s %s: render: %v", name, version, err)
		}
		if version == h.DefaultVersion {
			t.Errorf("%s: %s is the OpenShell default, not a kit release", name, version)
		}
	}
	if HarnessRelease("claudecode") != "" {
		t.Error("Claude Code is installed by the kit's file pin, not the harness")
	}
}
