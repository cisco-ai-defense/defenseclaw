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

// GAP-0667 (GAP-0651): Devin serves only its current build, so the kit's
// release, the OpenShell image's default and the reviewed-build alias that
// gives the release a sandbox hook contract are one version. A pin moved in
// one place and not the others builds an image from an archive Devin no
// longer serves, or an actor whose hooks have no contract.
func TestGAP0667DevinPinsAgree(t *testing.T) {
	h, ok := harness.Get("devin")
	if !ok {
		t.Fatal("no devin harness")
	}
	kit := HarnessReleases["devin"]
	if kit == "" || kit != h.DefaultVersion {
		t.Fatalf("the kit installs Devin %q and the OpenShell image %q", kit, h.DefaultVersion)
	}
	steps, err := h.InstallSteps(kit)
	if err != nil || len(steps) == 0 || !strings.Contains(steps[0].Run, kit) {
		t.Fatalf("no install step for Devin %s: %v", kit, err)
	}
	if res := connector.ResolveSandboxHookContract("devin", kit); res.Status != connector.HookCompatibilityKnown {
		t.Errorf("Devin %s has no sandbox hook contract (substrateReviewedBuilds): %+v", kit, res)
	}
}
