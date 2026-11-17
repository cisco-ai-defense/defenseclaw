// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/attest"
	"github.com/defenseclaw/defenseclaw/internal/substrate/controller"
	"github.com/defenseclaw/defenseclaw/internal/substrate/kit"
)

// specAttest attests a one-container template of a clean, signed image
// whose attested entrypoint is the relay.
func specAttest(t *testing.T, c *ateapi.Container) controller.Attestation {
	t.Helper()
	img := "reg.example.com/dc/claude@" + digA
	v := verified(digA, "1.0.10", time.Now().Add(time.Hour))
	v.Entrypoint = []string{kit.RelayBinary, "serve"}
	ta := &controller.TemplateAttestor{
		Verifier:   fakeVerifier{by: map[string]*attest.Verified{img: v}},
		Registries: []string{"reg.example.com"},
	}
	c.Image = img
	att, err := ta.Attest(context.Background(), &ateapi.ActorTemplate{
		Metadata:   &ateapi.ResourceMetadata{Atespace: "a", Name: "t"},
		Containers: []*ateapi.Container{c}})
	if err != nil {
		t.Fatal(err)
	}
	return att
}

// Acceptance test of the RKRELAY review (GAP-0354): a signed, clean image
// was admitted with LD_PRELOAD or git's command-line configuration in the
// template's env, or with its entrypoint (the relay) replaced.
func TestRKTemplateEnvAndCommandAreChecked(t *testing.T) {
	for name, c := range map[string]*ateapi.Container{
		"env LD_PRELOAD": {Env: []*ateapi.EnvVar{{Name: "LD_PRELOAD", Value: "/tmp/x.so"}}},
		"env GIT_CONFIG": {Env: []*ateapi.EnvVar{{Name: "GIT_CONFIG_COUNT", Value: "1"},
			{Name: "GIT_CONFIG_KEY_0", Value: "core.fsmonitor"}, {Name: "GIT_CONFIG_VALUE_0", Value: "/tmp/x.sh"}}},
		"command override": {Command: []string{"/bin/sh", "-c", "exec /usr/local/bin/claude"}},
	} {
		if att := specAttest(t, c); att.Attested || !att.Allowlist {
			t.Errorf("%s: template admitted (attested=%v reason=%q)", name, att.Attested, att.Reason)
		}
	}
}

// GAP-0354: the refusal names the field and the variable, never the value.
func TestTemplateSpecRefusalsNameTheField(t *testing.T) {
	for _, c := range []struct {
		name string
		c    *ateapi.Container
		want []string
	}{
		{"unexpected env", &ateapi.Container{Env: []*ateapi.EnvVar{{Name: "PERLLIB", Value: "/tmp/secret-path"}}},
			[]string{"container 0: env", "PERLLIB (not on the allowlist)"}},
		{"kit variable, other value", &ateapi.Container{Env: []*ateapi.EnvVar{{Name: "SSL_CERT_FILE", Value: "/tmp/ca.pem"}}},
			[]string{"SSL_CERT_FILE (the kit sets it to \"" + kit.TrustBundle + "\" only)"}},
		{"different command", &ateapi.Container{Command: []string{"/bin/sh"}},
			[]string{"container 0: command [\"/bin/sh\"] is not the attested entrypoint"}},
		{"extra args", &ateapi.Container{Args: []string{"--debug"}},
			[]string{"container 0: args [\"--debug\"] are not the attested arguments"}},
	} {
		att := specAttest(t, c.c)
		if att.Attested || !att.Allowlist {
			t.Errorf("%s: admitted", c.name)
			continue
		}
		for _, w := range c.want {
			if !strings.Contains(att.Reason, w) {
				t.Errorf("%s: reason %q lacks %q", c.name, att.Reason, w)
			}
		}
		if strings.Contains(att.Reason, "secret-path") {
			t.Errorf("%s: the reason shows the value: %q", c.name, att.Reason)
		}
	}
}

// GAP-0354: the kit's own variables, ordinary settings, and the attested
// entrypoint spelled out are admitted.
func TestTemplateSpecKitVariablesAndEntrypointPass(t *testing.T) {
	for name, c := range map[string]*ateapi.Container{
		"kit env": {Env: []*ateapi.EnvVar{{Name: "LANG", Value: "C.UTF-8"}, {Name: "SSL_CERT_FILE", Value: kit.TrustBundle},
			{Name: "XDG_CONFIG_HOME", Value: kit.XDGConfigHome}, {Name: "DISABLE_TELEMETRY", Value: "1"},
			{Name: "ANTHROPIC_API_KEY", Value: kit.PlaceholderSecret}}},
		"attested command": {Command: []string{kit.RelayBinary, "serve"}},
		"nothing set":      {},
	} {
		if att := specAttest(t, c); !att.Attested || att.Allowlist {
			t.Errorf("%s: refused: %q", name, att.Reason)
		}
	}
}
