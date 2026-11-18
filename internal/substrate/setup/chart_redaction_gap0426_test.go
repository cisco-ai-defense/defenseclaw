// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"bytes"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/redaction"
)

// chartGatewayConfig is the gateway's config.yaml in a render.
func chartGatewayConfig(t *testing.T, out []byte) []byte {
	t.Helper()
	for _, o := range decodeObjects(t, out) {
		if o.Kind == "ConfigMap" && o.Metadata["name"] == "defenseclaw-config" {
			raw, _ := o.Data["config.yaml"].(string)
			return []byte(raw)
		}
	}
	t.Fatal("no defenseclaw-config ConfigMap")
	return nil
}

// chartLocalProfiles compiles the rendered config the way the gateway does
// and returns the profile of local history (the audit store) per bucket.
func chartLocalProfiles(t *testing.T, raw []byte) map[observability.Bucket]redaction.ProfileName {
	t.Helper()
	compiled, err := config.ParseCompileObservabilityV8("config.yaml", raw, config.ObservabilityV8CompileOptions{DefaultDataDir: t.TempDir()})
	if err != nil {
		t.Fatalf("the rendered config does not compile: %v", err)
	}
	out := map[observability.Bucket]redaction.ProfileName{}
	for _, b := range observability.Buckets() {
		p, err := compiled.Plan.ResolveLocalRedactionProfile(b)
		if err != nil {
			t.Fatal(err)
		}
		out[b] = p
	}
	return out
}

// GAP-0426: the cluster gateway's audit store held plain-text secrets in
// llm_prompt, llm_response and tool_invocation rows, because every bucket
// used profile none (the laptop default, where the history is the user's
// own). The chart now makes sensitive the default for every bucket, local
// history included, so a credential in a prompt, an answer or a tool result
// is replaced before it is written; config and the chart value still win.
func TestChartRedactsSecretsInTheGatewayStoreGAP0426(t *testing.T) {
	helm := helmBinary(t)
	for _, c := range []string{"default", "full", "launcher", "person-secrets"} {
		for b, p := range chartLocalProfiles(t, chartGatewayConfig(t, renderChart(t, helm, c))) {
			if p != redaction.ProfileSensitive {
				t.Errorf("%s: bucket %s keeps local history with profile %q, want sensitive", c, b, p)
			}
		}
	}
	for set, want := range map[string]redaction.ProfileName{
		"observability.redactionProfile=none":                    redaction.ProfileNone,
		"config.observability.defaults.redaction_profile=strict": redaction.ProfileStrict,
	} {
		for b, p := range chartLocalProfiles(t, chartGatewayConfig(t, renderChart(t, helm, "default", "--set", set))) {
			if p != want {
				t.Errorf("--set %s: bucket %s profile %q, want %q", set, b, p, want)
			}
		}
	}

	// What sensitive does to the text of a prompt or a tool result.
	profile, ok := redaction.BuiltInProfile(redaction.ProfileSensitive)
	if !ok {
		t.Fatal("no sensitive profile")
	}
	// Real-format values (a detector matches the provider's format and
	// rejects degenerate runs).
	secrets := []string{
		"AKIAZ3Q7XK9M2P4W8R5T",
		"ghp_Zq8xR2mN7vK4tL9wB3cY6hJ1pD5sF0gA2eUi",
		"sub-J22-bearer-canary-7f3a9c",
	}
	text := "Write(.env) wrote:\nAWS_ACCESS_KEY_ID=" + secrets[0] + "\nGITHUB_TOKEN=" + secrets[1] +
		"\nAuthorization: Bearer " + secrets[2] + "\n"
	key := bytes.Repeat([]byte{0x42}, 32)
	for _, class := range []observability.FieldClass{observability.FieldClassContent, observability.FieldClassEvidence} {
		res, err := redaction.DetectAndRedact(text, class, profile.DetectorGroups(), key, nil)
		if err != nil {
			t.Fatalf("%s: %v", class, err)
		}
		for _, s := range secrets {
			if strings.Contains(res.Value, s) {
				t.Errorf("%s: sensitive keeps %q in %q", class, s[:6], res.Value)
			}
		}
		if !strings.Contains(res.Value, "Write(.env) wrote:") {
			t.Errorf("%s: sensitive removed the surrounding text: %q", class, res.Value)
		}
	}
}
