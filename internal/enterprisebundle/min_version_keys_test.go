// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisebundle_test

import (
	"context"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
)

const trustedConnectorBundleKeys = "  identity:\n    trusted_connectors:\n      - name: gas\n        account: svc-gas\n" +
	"        may_act_for:\n          groups: [agents-users]\n"

// Sign-time lint: a bundle that sets a key only 1.0.6 reads must carry
// min_product_version 1.0.6 or later.
func TestComposeRequiresProductFloorForTrustedConnectors(t *testing.T) {
	config := strings.Replace(bundleConfig(t), "  profile: standalone\n", "  profile: standalone\n"+trustedConnectorBundleKeys, 1)
	for _, tc := range []struct {
		min    string
		refuse bool
	}{{"", true}, {"1.0.5", true}, {"1.0.6", false}, {"1.1.0", false}} {
		root, b := writeBundle(t, config)
		in := enterprisebundle.ComposeInput{
			Bundle: b, Root: root, BundleID: tamperBundleID, TenantID: "acme", DeviceGroup: "eng", Version: 5,
			Platforms: []string{enterprisebundle.PlatformLinux}, CreatedAt: signedAt, CreatedBy: "operator:alice",
			MinProductVersion: tc.min, ProductVersion: "1.0.6", HostPlatform: enterprisebundle.PlatformLinux, Digester: digester,
		}
		_, _, err := enterprisebundle.Compose(context.Background(), in)
		if tc.refuse {
			if enterprisebundle.CodeOf(err) != enterprisebundle.CodeConfigInvalid || !strings.Contains(errString(err), "trusted_connectors") {
				t.Errorf("min %q: got %v, want config_invalid naming trusted_connectors", tc.min, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("min %q: %v", tc.min, err)
		}
	}
	for name, key := range map[string]string{
		"agent_gateway": "connectors:\n  agent_gateway:\n    enabled: true\n",
		"root_scope":    "guardrail:\n  chains:\n    root_scope: true\n",
	} {
		root, b := writeBundle(t, mergeTopLevel(bundleConfig(t), key))
		in := enterprisebundle.ComposeInput{
			Bundle: b, Root: root, BundleID: tamperBundleID, TenantID: "acme", DeviceGroup: "eng", Version: 5,
			Platforms: []string{enterprisebundle.PlatformLinux}, CreatedAt: signedAt, CreatedBy: "operator:alice",
			ProductVersion: "1.0.6", HostPlatform: enterprisebundle.PlatformLinux, Digester: digester,
		}
		if _, _, err := enterprisebundle.Compose(context.Background(), in); !strings.Contains(errString(err), name) {
			t.Errorf("%s without a floor: got %v", name, err)
		}
	}
}

// mergeTopLevel adds a top-level block to config, or merges a guardrail
// block into the existing one.
func mergeTopLevel(config, block string) string {
	if strings.HasPrefix(block, "guardrail:\n") && strings.Contains(config, "\nguardrail:\n") {
		return strings.Replace(config, "\nguardrail:\n", "\n"+block, 1)
	}
	return config + block
}

// An older signed bundle that still lists a removed trusted connector is
// refused by the version floor once a newer bundle is confirmed.
func TestOlderBundleWithRemovedConnectorRefusedByFloor(t *testing.T) {
	older := &enterprisebundle.Manifest{BundleID: tamperBundleID, Version: 5}
	confirmed := enterprisebundle.Confirmed{Version: 6, BundleID: tamperBundleID, ManifestSHA256: strings.Repeat("a", 64)}
	if _, _, err := enterprisebundle.CheckFloor(older, strings.Repeat("b", 64), confirmed, 0); enterprisebundle.CodeOf(err) != enterprisebundle.CodeVersionNotNewer {
		t.Fatalf("an older bundle was not refused by the floor: %v", err)
	}
}
