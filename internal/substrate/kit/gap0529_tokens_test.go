// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package kit

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
)

// GAP-0529, B1 S7: registry placeholders are no longer baked into the
// kit's npmrc at template build (a new registry needed a rebuild). The
// launcher writes them in the agent's ~/.npmrc at each start
// (substratecli/workspace registry.go). The kit's global npmrc keeps its
// settings and holds no token line.
func TestGAP0529KitNpmrcHoldsNoRegistryToken(t *testing.T) {
	h, ok := harness.Get("claudecode")
	if !ok {
		t.Fatal("no claudecode harness")
	}
	art, err := SubstrateArtifacts(h.Provider, h.DefaultVersion, DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	ov, err := ActorOverlay(art, OverlayOptions{Config: DefaultConfig(), Home: "/sandbox", Workdir: "/work"})
	if err != nil {
		t.Fatal(err)
	}
	rc := string(file(ov, NPMGlobalConfig))
	if strings.Contains(rc, "_authToken") || !strings.Contains(rc, "fund=false\n") {
		t.Errorf("kit npmrc:\n%s", rc)
	}
}

// TestB1S7NPMCredential: the template build and the agent start refuse
// the same npmrc lines.
func TestB1S7NPMCredential(t *testing.T) {
	for line, want := range map[string]string{
		"//r.example/:_authToken=abc": "//r.example/:_authToken", "_auth = x": "_auth",
		"//r.example/:_authToken=${NPM_TOKEN}": "", "registry=https://r.example/": "", "# _authToken=abc": "", "": "",
	} {
		if k, _ := NPMCredential(line); k != want {
			t.Errorf("NPMCredential(%q) = %q, want %q", line, k, want)
		}
	}
}
