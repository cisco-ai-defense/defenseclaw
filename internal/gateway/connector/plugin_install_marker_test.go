// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

func TestManagedPluginInstallMarkerRequiresAManagedAbsolutePath(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "DefenseClaw-HookRuntime")
	if got := managedPluginInstallMarker(SetupOpts{ManagedEnterprise: true, ManagedInstallMarker: marker + string(filepath.Separator)}); got != marker {
		t.Fatalf("managed marker = %q, want %q", got, marker)
	}
	for _, opts := range []SetupOpts{
		{ManagedInstallMarker: marker},
		{ManagedEnterprise: true, ManagedInstallMarker: "DefenseClaw-HookRuntime"},
		{ManagedEnterprise: true},
	} {
		if got := managedPluginInstallMarker(opts); got != "" {
			t.Fatalf("marker for %+v = %q, want none", opts, got)
		}
	}
}

// After an uninstall the OpenCode plugin stays in a signed-out user's profile
// with a closed fail mode. Once the gateway is unreachable or the credential
// is gone AND the administrator-owned install marker is gone, it must allow
// instead of blocking every tool call, at the gateway call and at the
// foreign-hook guard; while the marker exists it still fails closed, and a
// render without a marker never relaxes.
func TestOpenCodePluginStopsFailingClosedOnceTheDeploymentIsRemoved(t *testing.T) {
	nodeForTest(t)
	root := testenv.PrivateTempDir(t)
	marker := filepath.Join(root, "DefenseClaw-HookRuntime")
	if err := os.MkdirAll(marker, 0o700); err != nil {
		t.Fatal(err)
	}
	tokenPath := filepath.Join(root, "opencode.token")
	writeToken := func() {
		t.Helper()
		if err := os.WriteFile(tokenPath, []byte(strings.Repeat("a", 64)+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeToken()
	// A port that was just released: nothing answers there.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	unreachable := listener.Addr().String()
	_ = listener.Close()

	tmpl, err := hookFS.ReadFile("hooks/opencode-plugin.js")
	if err != nil {
		t.Fatal(err)
	}
	render := func(name, markerValue string) string {
		t.Helper()
		rendered, err := renderTemplate(string(tmpl), templateData{
			APIAddr:         unreachable,
			TokenFileJS:     javaScriptStringContent(tokenPath),
			InstallMarkerJS: javaScriptStringContent(markerValue),
			FailMode:        "closed",
			Managed:         true,
		})
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, []byte(rendered), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	withMarker := render("with-marker.mjs", marker)
	withoutMarker := render("without-marker.mjs", "")

	harness := `
import { pathToFileURL } from "node:url";
import { createInterface } from "node:readline";
const plugins = [];
for (const path of process.argv.slice(1)) {
  const loaded = await import(pathToFileURL(path).href);
  plugins.push(await loaded.DefenseClaw({ directory: "" }));
}
console.log("` + nodeHarnessReady + `");
const lines = createInterface({ input: process.stdin, crlfDelay: Infinity });
for await (const line of lines) {
  const plugin = plugins[Number(line)];
  try {
    await plugin["tool.execute.before"](
      { tool: "Bash", sessionID: "S", messageID: "M", callID: "C" },
      { args: { command: "printf marker" } },
    );
    console.log("allow");
  } catch (error) {
    console.log("block:" + String(error && error.message || error));
  }
}
`
	session := startNodeHarnessSession(t, harness, withMarker, withoutMarker)
	evaluate := func(step string, plugin int) string {
		t.Helper()
		return session.request(step, strconv.Itoa(plugin))
	}

	if got := evaluate("installed, gateway down", 0); !strings.HasPrefix(got, "block:DefenseClaw hook failed closed") {
		t.Fatalf("installed deployment with the gateway down = %q, want a fail-closed block", got)
	}
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	if got := evaluate("uninstalled, gateway gone", 0); got != "allow" {
		t.Fatalf("uninstalled deployment = %q, want allow", got)
	}
	if got := evaluate("no marker rendered", 1); !strings.HasPrefix(got, "block:DefenseClaw hook failed closed") {
		t.Fatalf("plugin without a marker = %q, want an unconditional fail-closed block", got)
	}
	if err := os.Remove(tokenPath); err != nil {
		t.Fatal(err)
	}
	if got := evaluate("uninstalled, credential gone", 0); got != "allow" {
		t.Fatalf("uninstalled deployment without a credential = %q, want allow", got)
	}
	if err := os.MkdirAll(marker, 0o700); err != nil {
		t.Fatal(err)
	}
	if got := evaluate("installed, credential gone", 0); got != "block:DefenseClaw hook credential is unavailable." {
		t.Fatalf("installed deployment without a credential = %q, want the credential block", got)
	}
	session.close()

	// The foreign-hook guard's binary is removed with the marker: a guard
	// that cannot run blocks while the marker exists or none was rendered,
	// and allows once the deployment is gone.
	writeToken()
	missingGuard := filepath.Join(root, "bin", "defenseclaw-hook")
	for _, tc := range []struct{ name, marker, want string }{
		{"installed", marker, "block:DefenseClaw could not check for unapproved plugins"},
		{"uninstalled", filepath.Join(root, "removed-HookRuntime"), "allow"},
		{"no marker rendered", "", "block:DefenseClaw could not check for unapproved plugins"},
	} {
		lines := runOpenCodePluginHarness(t, templateData{
			APIAddr:            unreachable,
			TokenFileJS:        javaScriptStringContent(tokenPath),
			ForeignHookGuardJS: javaScriptStringContent(missingGuard),
			InstallMarkerJS:    javaScriptStringContent(tc.marker),
			FailMode:           "closed",
			Managed:            true,
		}, 1)
		if !strings.HasPrefix(lines[0], tc.want) {
			t.Fatalf("guard, %s deployment = %q, want %q", tc.name, lines[0], tc.want)
		}
	}
}
