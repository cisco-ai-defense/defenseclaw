// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
)

// A managed bundle that omits gateway.api_bind digests like one that spells
// out 127.0.0.1, the only bind a managed gateway accepts and the value the
// running gateway loads. Before GAP-0007 the offline loader left the bind
// empty, so the signed digest differed from the gateway digest and every
// apply of such a bundle failed digest_mismatch and rolled back.
func TestBundleDigestOfOmittedManagedListenerMatchesSpelledOut(t *testing.T) {
	const policy = "config_version: 9\ndeployment_mode: managed_enterprise\nenterprise:\n  profile: standalone\n" +
		"guardrail:\n  enabled: true\n  mode: observe\n  rule_pack: default\n  connectors:\n    codex: {}\n"
	digest := func(t *testing.T, platform, raw string) string {
		t.Helper()
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, enterprisebundle.ConfigName), []byte(raw), 0o600); err != nil {
			t.Fatal(err)
		}
		b, err := enterprisebundle.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		cfg, rendered, err := enterprisebundle.LoadConfigForPlatform(b, dir, platform)
		if err != nil {
			t.Fatalf("load: %v", err)
		}
		if cfg.Gateway.APIBind != "127.0.0.1" || cfg.Gateway.APIPort != 18970 {
			t.Fatalf("loaded listener %q:%d, want 127.0.0.1:18970", cfg.Gateway.APIBind, cfg.Gateway.APIPort)
		}
		p, err := ComputeEffectivePolicyFor(context.Background(), cfg, EffectivePolicyOptions{GOOS: platform, BundleRoot: dir, Raw: rendered})
		if err != nil {
			t.Fatal(err)
		}
		return p.Digest
	}
	for _, platform := range []string{"linux", "darwin"} {
		t.Run(platform, func(t *testing.T) {
			spelled := digest(t, platform, "gateway:\n  api_bind: 127.0.0.1\n  api_port: 18970\n"+policy)
			for name, raw := range map[string]string{
				"no gateway block": policy,
				"port only":        "gateway:\n  api_port: 18970\n" + policy,
			} {
				if got := digest(t, platform, raw); got != spelled {
					t.Fatalf("%s: digest %s, spelled-out listener %s", name, got, spelled)
				}
			}
		})
	}
}
