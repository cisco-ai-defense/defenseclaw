// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"encoding/json"
	"path/filepath"
	"regexp"
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

var renderedPluginGatewayBinaryRE = regexp.MustCompile(`const DC_GATEWAY_BINARY(?:: string)? = "((?:[^"\\]|\\.)*)"`)

// renderedPluginGatewayBinary returns the DC_GATEWAY_BINARY a rendered
// plugin bakes, decoded from its JavaScript string.
func renderedPluginGatewayBinary(t *testing.T, name string, body []byte) string {
	t.Helper()
	match := renderedPluginGatewayBinaryRE.FindSubmatch(body)
	if match == nil {
		t.Fatalf("%s: rendered plugin has no DC_GATEWAY_BINARY", name)
	}
	var value string
	if err := json.Unmarshal([]byte(`"`+string(match[1])+`"`), &value); err != nil {
		t.Fatalf("%s: DC_GATEWAY_BINARY %q: %v", name, match[1], err)
	}
	return value
}

// GAP-1847: on a native Windows Setup install the per-user OpenCode and Amp
// plugins post through the gateway in Setup's install root (InstallRoot\bin),
// the install that rendered them, not ~/.local/bin, which Setup does not
// create. install.sh, install.ps1 and every managed or Secure Client render
// keep "" (the ~/.local/bin gateway, or no per-user helper at all), so Linux
// and macOS render exactly what they did.
func TestPerUserPluginPostsThroughTheInstallGateway(t *testing.T) {
	plugins := map[string]*hookOnlyConnector{"amp": NewAMPConnector().hookOnlyConnector, "opencode": NewOpenCodeConnector()}
	want := ""
	if runtime.GOOS == "windows" {
		launcher := canonicalNativeWindowsHookBinary()
		want = canonicalNativeWindowsInstalledGatewayBinary()
		if launcher == "" || want == "" {
			t.Fatal("no native Setup launcher or gateway path on this host")
		}
		t.Cleanup(PinNativeHookExecutableForTest(launcher))
	}
	render := func(name string, c *hookOnlyConnector, opts SetupOpts) string {
		t.Helper()
		body, err := c.renderPluginArtifact(opts)
		if err != nil {
			t.Fatalf("%s: render: %v", name, err)
		}
		return renderedPluginGatewayBinary(t, name, body)
	}
	for name, c := range plugins {
		perUser := SetupOpts{DataDir: filepath.Join(testenv.PrivateTempDir(t), ".defenseclaw"), APIAddr: "127.0.0.1:18970"}
		if got := render(name, c, perUser); got != want {
			t.Errorf("%s per-user: DC_GATEWAY_BINARY %q, want %q", name, got, want)
		}
		for _, layout := range []string{"unix", "windows"} {
			managedOpts := managedPluginOutageOpts(t, name, layout, "closed", filepath.Join(testenv.PrivateTempDir(t), "defenseclaw-hook"), "127.0.0.1:18970")
			if got := render(name, c, managedOpts); got != "" {
				t.Errorf("%s managed %s: DC_GATEWAY_BINARY %q, want empty", name, layout, got)
			}
		}
	}
	if runtime.GOOS != "windows" {
		return
	}
	// An install.ps1 install registers its ~/.local/bin launcher and keeps
	// the ~/.local/bin gateway.
	t.Cleanup(PinNativeHookExecutableForTest(filepath.Join(userHomeDir(), ".local", "bin", windowsHookBinaryName)))
	for name, c := range plugins {
		perUser := SetupOpts{DataDir: filepath.Join(testenv.PrivateTempDir(t), ".defenseclaw"), APIAddr: "127.0.0.1:18970"}
		if got := render(name, c, perUser); got != "" {
			t.Errorf("%s install.ps1 per-user: DC_GATEWAY_BINARY %q, want empty", name, got)
		}
	}
}
