// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package kit

import (
	"regexp"
	"strings"
	"testing"
)

// GAP-0529: npm reads its global configuration from <prefix>/etc/npmrc, and
// a distribution node's prefix is /usr, so the kit's npmrc at
// /usr/local/etc/npmrc was never read in the claudecode image (npm config
// get globalconfig: /usr/etc/npmrc). Every connector's image names the
// kit's file in npm_config_globalconfig, the file is root-owned and in
// relay.protected, and the actor allowlist fixes the value.
func TestGAP0529NPMReadsTheKitsNpmrc(t *testing.T) {
	const file = "/usr/local/etc/npmrc"
	if r := ImageEnv()["npm_config_globalconfig"]; !r.Fixed || r.Value != file {
		t.Fatalf("actor allowlist rule for npm_config_globalconfig = %+v, want fixed %s", r, file)
	}
	for _, c := range Connectors() {
		ov := wave2Overlay(t, c)
		if got := ov.Env["npm_config_globalconfig"]; got != file {
			t.Errorf("%s: npm_config_globalconfig = %q, want %s (npm otherwise reads <prefix>/etc/npmrc)", c, got, file)
		}
		found := false
		for _, f := range ov.Files {
			if f.Path == file {
				found = !f.User
			}
		}
		if !found {
			t.Errorf("%s: no root-owned %s in the overlay", c, file)
		}
	}
}

// GAP-0525: an EKS microVM actor's agent environment showed
// CLAUDE_CODE_MESSAGING_TOKEN. Claude Code creates it per session for its
// own local inbox socket and exports it to its tool processes; the kit does
// not set it. The kit's actor environment holds no credential value: every
// credential-shaped variable it sets is a placeholder or a fixed
// identifier from the allowlist, in every connector's image and in the
// agent's environment the relay adds.
func TestGAP0525KitEnvironmentHoldsNoCredential(t *testing.T) {
	credential := regexp.MustCompile(`(?i)(TOKEN|SECRET|PASSWORD|CREDENTIAL|API_KEY|_KEY$|AUTH)`)
	rules := ImageEnv()
	for _, c := range Connectors() {
		ov := wave2Overlay(t, c)
		env := map[string]string{}
		for k, v := range ov.Env {
			env[k] = v
		}
		for k, v := range wave2RelayEnv[c] {
			env[k] = v
		}
		for k, v := range env {
			if strings.HasPrefix(k, "CLAUDE_CODE_MESSAGING_") {
				t.Errorf("%s: the kit sets %s", c, k)
			}
			if !credential.MatchString(k) {
				continue
			}
			r, ok := rules[k]
			if !ok || !r.Fixed || r.Value != v {
				t.Errorf("%s: %s is credential-shaped and not a fixed allowlist value (%+v)", c, k, r)
				continue
			}
			if v != PlaceholderSecret && len(v) >= 20 {
				t.Errorf("%s: %s=%d chars is neither the placeholder nor a short fixed identifier", c, k, len(v))
			}
		}
	}
}
