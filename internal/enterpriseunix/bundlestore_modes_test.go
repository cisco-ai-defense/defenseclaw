// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// GAP-0082: other accounts cannot list the bundle store (version, staging
// and inbox names), and the public receipt stays readable by name. Checked
// after install, after a bundle apply and after a rollback.
func TestBundleStoreIsUnlistableButTheReceiptStaysPublic(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			b := newBundleHost(t, goos)
			store := filepath.Join(b.env.Layout.ConfigDir, enterprisebundle.BundlesDirName)
			check := func(phase string, receipt bool) {
				t.Helper()
				if got := b.mode(store); got != 0o711 {
					t.Fatalf("%s: bundle store mode %04o, want 0711", phase, got)
				}
				if receipt {
					if got := b.mode(filepath.Join(store, enterprisestatus.PublicReceiptName)); got != 0o644 {
						t.Fatalf("%s: receipt.json mode %04o, want 0644", phase, got)
					}
				}
			}
			check("install", false)
			v1, v2, _ := bundleConfigs(b.testHost)
			requireOK(t, b.apply(b.dir(1, v1)))
			check("apply", true)
			b.frozen, _ = installedPolicy(b)
			b.reloadError = "rule pack refused"
			requireError(t, b.apply(b.dir(2, v2)), codeBundleNotConfirmed)
			check("rollback", true)
		})
	}
}
