// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"testing"
)

// TestT20BPackOwnPostureReadsTiersStrictly (DET111 T19 review P3-3, T20
// P3-7): a legacy folder named strict with a tiers.yaml the loader refuses
// (an unknown row, a wrong version, an unknown field) named its tier from
// that file (permissive) for the standalone hook and the outage fail mode.
// The file is now read as the loader reads it: refused, it names no tier
// and the folder keeps strict. A valid column still names its tier. Red at
// 06f1da5b94.
func TestT20BPackOwnPostureReadsTiersStrictly(t *testing.T) {
	for _, tc := range []struct{ name, column, want string }{
		{"unknown-row", "version: 1\ntier: permissive\nrows:\n  - id: no-such-row\n    per_user: {floor: allow}\n    managed: {floor: allow}\n", ""},
		{"wrong-version", "version: 2\ntier: permissive\nrows: []\n", ""},
		{"unknown-field", "version: 1\ntier: permissive\nextra: 1\nrows: []\n", ""},
		{"valid", "version: 1\ntier: permissive\nrows: []\n", HookPolicyTierPermissive},
	} {
		dir := filepath.Join(t.TempDir(), "strict")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "tiers.yaml"), []byte(tc.column), 0o644); err != nil {
			t.Fatal(err)
		}
		if got := packOwnPosture(dir); got != tc.want {
			t.Errorf("%s: packOwnPosture = %q, want %q", tc.name, got, tc.want)
		}
	}
}
