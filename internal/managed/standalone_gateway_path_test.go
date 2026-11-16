// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package managed

import "testing"

// On Linux and macOS defenseclaw-gateway is not on the PATH, so every hint
// names it by this path (cowork-1-0-8 GAP-0081).
func TestStandaloneGatewayPath(t *testing.T) {
	for goos, want := range map[string]string{
		"linux":   "/opt/defenseclaw/bin/defenseclaw-gateway",
		"darwin":  "/opt/cisco/defenseclaw/bin/defenseclaw-gateway",
		"windows": "defenseclaw-gateway",
		"":        "defenseclaw-gateway",
	} {
		if got := StandaloneGatewayPath(goos); got != want {
			t.Errorf("StandaloneGatewayPath(%q) = %q, want %q", goos, got, want)
		}
	}
	for _, goos := range []string{"linux", "darwin"} {
		layout, err := StandaloneLayoutFor(goos)
		if err != nil {
			t.Fatal(err)
		}
		if got, want := StandaloneGatewayPath(goos), layout.BinDir+"/"+StandaloneGatewayBinary; got != want {
			t.Errorf("%s path %q does not follow the layout BinDir: want %q", goos, got, want)
		}
	}
}
