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
// guard. It keeps the templates its release pins: the *-secure-client copies
// are the bdcb9cf6 templates byte for byte (their SHA-256 values are also the
// ones the plugin scanner recognizes, cli/defenseclaw/scanner/plugin_scanner/
// self_identity.py), and their render with these inputs is pinned.
func TestSecureClientPluginTemplatesArePinned(t *testing.T) {
	for _, tc := range []struct {
		current, pinned, templateSHA, renderSHA string
	}{
		{
			current: "opencode-plugin.js", pinned: "opencode-plugin-secure-client.js",
			templateSHA: "f81b5b2f208d2535ac028c49bc95941d5666bee72315053386c05cd9411e34de",
			renderSHA:   "359d66dfab43e5fb75c16aaa6c6742bf8f5f0dfe38a5286108c4c844a4e235bb",
		},
		{
			current: "amp-plugin.ts", pinned: "amp-plugin-secure-client.ts",
			templateSHA: "392bc21bb99d9978b69683dca8fd022d074037a1e9df6f885916c6525537cdd6",
			renderSHA:   "32c9be305de4484034ed6b18524864d85c2db9d268eb9afc6ad7cfe1aa94aa02",
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
			APIAddr:     "127.0.0.1:18970",
			TokenFileJS: javaScriptStringContent("/Users/sc-user/.defenseclaw/hooks/.hook-" + tc.current + ".token"),
			FailMode:    "closed",
			Managed:     true,
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
