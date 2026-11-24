// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package kit

import (
	"reflect"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
)

// GAP-0529: the kit's npmrc carries a placeholder token for each registry
// host a substrate.secrets entry injects the Authorization header on (npm
// sends a registry's _authToken there), so `npm install` from a bound
// private registry authenticates through egress injection with nothing
// typed. No other header, no host pattern, never a value.
// B1 S7: the launcher also writes them at agent start, but a launcher older
// than 1.0.11 does not, so the build keeps them (remove in 1.0.12, when launchers older than 1.0.11 are unsupported).
func TestGAP0529RegistryPlaceholdersInTheKitsNpmrc(t *testing.T) {
	secrets := []config.SubstrateSecret{
		{Name: "npm-private", Source: "ate-secret://k8s.io/p/ns/npm/token",
			Inject: config.SubstrateSecretInject{Hosts: []string{"t-reg.t.svc", "*.npm.example.com"}, Header: "Authorization", Prefix: "Bearer ", Placeholder: "DC_SECRET_NPM"}},
		{Name: "github", Source: "ate-secret://k8s.io/p/ns/gh/token",
			Inject: config.SubstrateSecretInject{Hosts: []string{"npm.pkg.github.com", "T-REG.t.svc"}, Header: "authorization"}},
		{Name: "api-key", Source: "ate-secret://k8s.io/p/ns/k/token",
			Inject: config.SubstrateSecretInject{Hosts: []string{"api.example.com"}, Header: "X-Api-Key", Placeholder: "DC_SECRET_KEY"}},
	}
	got := NPMRegistryTokens(secrets)
	want := []RegistryToken{{Host: "npm.pkg.github.com", Placeholder: PlaceholderSecret}, {Host: "t-reg.t.svc", Placeholder: "DC_SECRET_NPM"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("NPMRegistryTokens = %+v, want %+v", got, want)
	}
	h, ok := harness.Get("claudecode")
	if !ok {
		t.Fatal("no claudecode harness")
	}
	art, err := SubstrateArtifacts(h.Provider, h.DefaultVersion, DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	ov, err := ActorOverlay(art, OverlayOptions{Config: DefaultConfig(), Home: "/sandbox", Workdir: "/work", RegistryTokens: got})
	if err != nil {
		t.Fatal(err)
	}
	rc := string(file(ov, NPMGlobalConfig))
	for _, line := range []string{"//t-reg.t.svc/:_authToken=DC_SECRET_NPM\n", "//npm.pkg.github.com/:_authToken=" + PlaceholderSecret + "\n", "fund=false\n"} {
		if !strings.Contains(rc, line) {
			t.Errorf("npmrc does not hold %q:\n%s", line, rc)
		}
	}
	if strings.Count(rc, "_authToken=") != 2 || strings.Contains(rc, "api.example.com") || strings.Contains(rc, "*") {
		t.Errorf("npmrc names a host it should not:\n%s", rc)
	}
	// Without bound registries the file holds no token at all.
	plain, err := ActorOverlay(art, OverlayOptions{Config: DefaultConfig(), Home: "/sandbox", Workdir: "/work"})
	if err != nil {
		t.Fatal(err)
	}
	if rc := string(file(plain, NPMGlobalConfig)); strings.Contains(rc, "_authToken") {
		t.Errorf("npmrc without bound registries holds a token line:\n%s", rc)
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
