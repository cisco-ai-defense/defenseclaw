// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"testing"
)

// The Secure Client profile renders the OpenCode and Amp plugins (macOS
// supports both) as a managed install without the standalone foreign-hook
// guard. It pins the reviewed *-secure-client copies, including the native
// connected-service verifier (their SHA-256 values are also recognized by
// cli/defenseclaw/scanner/plugin_scanner/self_identity.py).
func TestSecureClientPluginTemplatesArePinned(t *testing.T) {
	for _, tc := range []struct {
		current, pinned, templateSHA, renderSHA string
	}{
		{
			current: "opencode-plugin.js", pinned: "opencode-plugin-secure-client.js",
			templateSHA: "35af25a1713050fe1c2e9dd9014a0fcda0d07caba350244360e9d2a31abdc08f",
			renderSHA:   "efe0e4b45c37d81b1ce61fbba06074992f20dd00f3500b5868dc43bea762af04",
		},
		{
			current: "amp-plugin.ts", pinned: "amp-plugin-secure-client.ts",
			templateSHA: "cf00f9f404c0711357f55535dd1062667d398acbf7603dfa15fa951d212b4d4b",
			renderSHA:   "fb90d638dda2013520e7719776ee009a82bc3b72c0b49b8512e485aa128b4630",
		},
	} {
		if got := secureClientPluginAssets[tc.current]; got != tc.pinned {
			t.Fatalf("%s: Secure Client asset = %q, want %q", tc.current, got, tc.pinned)
		}
		tmpl, err := hookFS.ReadFile("hooks/" + tc.pinned)
		if err != nil {
			t.Fatal(err)
		}
		if sum := sha256.Sum256(tmpl); hex.EncodeToString(sum[:]) != tc.templateSHA {
			t.Fatalf("%s changed: sha256 %x, want %s", tc.pinned, sum, tc.templateSHA)
		}
		rendered, err := renderTemplate(string(tmpl), templateData{
			APIAddr:            "127.0.0.1:18970",
			TokenFileJS:        javaScriptStringContent("/Users/sc-user/.defenseclaw/hooks/.hook-" + tc.current + ".token"),
			NativePostBinaryJS: javaScriptStringContent("/opt/cisco/secureclient/defenseclaw/bin/defenseclaw-gateway"),
			FailMode:           "closed",
			Managed:            true,
		})
		if err != nil {
			t.Fatal(err)
		}
		if sum := sha256.Sum256([]byte(rendered)); hex.EncodeToString(sum[:]) != tc.renderSHA {
			t.Fatalf("%s: the Secure Client render changed: sha256 %x, want %s", tc.pinned, sum, tc.renderSHA)
		}
		// Verification reads the ownership marker from the current template;
		// both must carry the same one.
		current, err := hookFS.ReadFile("hooks/" + tc.current)
		if err != nil {
			t.Fatal(err)
		}
		currentMarker, _, _ := bytes.Cut(current, []byte("\n"))
		pinnedMarker, _, _ := bytes.Cut(tmpl, []byte("\n"))
		if !bytes.Equal(currentMarker, pinnedMarker) {
			t.Fatalf("%s and %s carry different ownership markers", tc.current, tc.pinned)
		}
	}
}

// Only a managed install without the standalone guard is the Secure Client
// profile and renders the pinned template; per-user and standalone installs
// render the current one.
func TestPluginSecureClientProfileSelectsThePinnedTemplate(t *testing.T) {
	guard := filepath.Join(t.TempDir(), "defenseclaw-hook")
	conn := NewOpenCodeConnector()
	for _, tc := range []struct {
		opts  SetupOpts
		want  bool
		asset string
	}{
		{SetupOpts{}, false, "opencode-plugin.js"},
		{SetupOpts{ForeignHookGuardBinary: guard}, false, "opencode-plugin.js"},
		{SetupOpts{ManagedEnterprise: true}, true, "opencode-plugin-secure-client.js"},
		{SetupOpts{ManagedEnterprise: true, ForeignHookGuardBinary: guard}, false, "opencode-plugin.js"},
	} {
		if got := pluginSecureClientProfile(tc.opts); got != tc.want {
			t.Fatalf("pluginSecureClientProfile(%+v) = %v, want %v", tc.opts, got, tc.want)
		}
		if got := conn.pluginArtifactAssetFor(tc.opts); got != tc.asset {
			t.Fatalf("asset for %+v = %q, want %q", tc.opts, got, tc.asset)
		}
	}
}
