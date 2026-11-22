// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// These tests render the sandbox artifacts of an image, which OpenShell does not do on Windows hosts.
//go:build !windows

package kitspec

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/substrate/attest"
)

// GAP-0354, GAP-0355: the environment every connector's kit image carries
// is inside the actor environment allowlist (kit.ImageEnv), for every model
// route, so the allowlist refuses no kit image.
func TestEveryKitImageEnvironmentIsPermitted(t *testing.T) {
	for _, c := range []struct{ name, provider string }{
		{"claudecode", "bedrock"}, {"claudecode", "anthropic"}, {"codex", "openai"}, {"codex", "bedrock"},
		{"devin", ""}, {"cursor", ""}, {"kiro", ""}, {"amp", ""}, {"opencode", ""}, {"copilot", ""}, {"hermes", ""}, {"antigravity", ""},
	} {
		spec, _, err := Spec(Options{Connector: c.name, KitVersion: "1.0.10", Provider: c.provider, Model: "some-model",
			HookBinary: []byte("hook"), RelayBinary: []byte("relay"), MetadataOnly: true})
		if err != nil {
			t.Fatalf("%s/%s: %v", c.name, c.provider, err)
		}
		env := map[string]string{}
		for k, v := range spec.Env {
			env[k] = v
		}
		for k, v := range spec.PhoneHome {
			env[k] = v
		}
		if bad := attest.CheckEnv(env); len(bad) > 0 {
			t.Errorf("%s/%s: the kit image sets variables the allowlist refuses: %s", c.name, c.provider, attest.FormatEnvRefusals(bad))
		}
	}
}
