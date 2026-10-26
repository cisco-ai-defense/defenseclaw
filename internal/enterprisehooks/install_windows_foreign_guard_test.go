// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
	"golang.org/x/sys/windows"
)

// windowsGuardCaptureConnector stands in for the Amp and OpenCode plugin
// connectors and records the foreign-hook guard binary the generic Windows
// lifecycle hands them when it renders the plugin (Setup) and whenever it
// lays out or verifies the footprint (AgentPaths).
type windowsGuardCaptureConnector struct {
	windowsGenericPluginTokenTestConnector
	rendered *[]string
	seen     *[]string
}

func (c *windowsGuardCaptureConnector) Setup(ctx context.Context, opts connector.SetupOpts) error {
	*c.rendered = append(*c.rendered, opts.ForeignHookGuardBinary)
	return c.windowsGenericPluginTokenTestConnector.Setup(ctx, opts)
}

func (c *windowsGuardCaptureConnector) AgentPaths(opts connector.SetupOpts) connector.AgentPaths {
	*c.seen = append(*c.seen, opts.ForeignHookGuardBinary)
	return c.windowsGenericPluginTokenTestConnector.AgentPaths(opts)
}

// On Windows the Amp and OpenCode plugins are installed and verified by the
// generic managed lifecycle (platformInstall's and platformVerify's default
// branch), never by the cross-platform installer. The guard binary must
// reach both, or the plugins render DC_FOREIGN_GUARD as "" (skipping the
// guard) and verification never requires it. The capture connector takes a
// name the dispatch routes like Amp and OpenCode (not Claude, Codex, Cursor
// or Copilot) without the per-user agent discovery; it names no shipped
// connector.
func TestWindowsGenericLifecyclePassesTheForeignHookGuardToPlugins(t *testing.T) {
	fixture := newWindowsGenericCodexFixture(t)
	// A per-user plugin install makes the vendor folder above the hook
	// runtime readable by users. Point it at an Administrators-owned folder
	// of this test, not the host's C:\ProgramData\Cisco: a fresh runner has
	// none, and the test must not change a real install's ACL.
	pinWindowsTestHookRuntimeAncestor(t)
	// A name native Windows certifies: an uncertified plugin connector is
	// refused before its render (ConnectorSupportOnOS fails closed).
	const name = "amp"
	var rendered, seen []string
	registry := connector.NewRegistry()
	registry.RegisterBuiltin(&windowsGuardCaptureConnector{
		windowsGenericPluginTokenTestConnector: windowsGenericPluginTokenTestConnector{
			windowsGenericCodexTestConnector{configPath: fixture.config, name: name},
		},
		rendered: &rendered,
		seen:     &seen,
	})
	guard, err := windowsEnterpriseHookExecutable()
	if err != nil {
		t.Fatal(err)
	}
	opts := fixture.opts
	// The guardian binds Amp to the native image npm installs for the user.
	ampExe := filepath.Join(append([]string{opts.UserHome}, windowsStandaloneManagedExecutableRelative["amp"][0]...)...)
	if err := os.MkdirAll(filepath.Dir(ampExe), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ampExe, []byte("MZ"), 0o700); err != nil {
		t.Fatal(err)
	}
	opts.ConnectorName = name
	opts.AgentVersion = "0.7.0"
	opts.Registry = registry
	opts.ForeignHookGuardBinary = guard
	ctx := context.Background()

	if _, _, err := platformInstall(ctx, opts); err != nil {
		t.Fatalf("platformInstall: %v", err)
	}
	if len(rendered) != 1 || !sameWindowsEnterprisePath(rendered[0], guard) {
		t.Fatalf("the plugin render received guard %q, want %s", rendered, guard)
	}
	seen = nil
	if _, _, err := platformVerify(ctx, opts); err != nil {
		t.Fatalf("platformVerify: %v", err)
	}
	if len(seen) == 0 {
		t.Fatal("verification never laid out the plugin footprint")
	}
	for _, got := range seen {
		if !sameWindowsEnterprisePath(got, guard) {
			t.Fatalf("verification used guard %q, want %s", got, guard)
		}
	}

	relative := opts
	relative.ForeignHookGuardBinary = `bin\defenseclaw-hook.exe`
	if _, err := resolveWindowsGenericManagedTarget(relative); err == nil || !strings.Contains(err.Error(), "not absolute") {
		t.Fatalf("a relative guard binary must be refused: %v", err)
	}
	untrusted := opts
	untrusted.ForeignHookGuardBinary = `C:\Users\Public\defenseclaw-hook.exe`
	restoreTrust := windowsEnterpriseHookTrustCheck
	windowsEnterpriseHookTrustCheck = func(path string) error {
		if sameWindowsEnterprisePath(path, untrusted.ForeignHookGuardBinary) {
			return errTestUntrustedGuard
		}
		return nil
	}
	t.Cleanup(func() { windowsEnterpriseHookTrustCheck = restoreTrust })
	if _, err := resolveWindowsGenericManagedTarget(untrusted); err == nil || !strings.Contains(err.Error(), "trust check failed") {
		t.Fatalf("an untrusted guard binary must be refused: %v", err)
	}
	unset := opts
	unset.ForeignHookGuardBinary = ""
	target, err := resolveWindowsGenericManagedTarget(unset)
	if err != nil || target.setup.ForeignHookGuardBinary != "" {
		t.Fatalf("an install without the guard (Secure Client, per-user) renders unchanged: %v %q", err, target.setup.ForeignHookGuardBinary)
	}
}

var errTestUntrustedGuard = errors.New("test: untrusted guard binary")

// pinWindowsTestHookRuntimeAncestor points the hook runtime vendor folder at
// a new folder under ProgramData (stock trusted ancestors) that
// Administrators own with an explicit DACL, as an installer leaves
// C:\ProgramData\Cisco, and removes it after the test.
func pinWindowsTestHookRuntimeAncestor(t *testing.T) {
	t.Helper()
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("the hook runtime vendor folder is administrator-only; run elevated")
	}
	programData, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if err != nil {
		t.Fatal(err)
	}
	base, err := os.MkdirTemp(programData, "dc-trust-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	testenv.SetSecurity(t, base, testenv.AdminOnlySDDL)
	vendor := filepath.Join(base, "Cisco")
	if err := os.Mkdir(vendor, 0o755); err != nil {
		t.Fatal(err)
	}
	testenv.SetSecurity(t, vendor, testenv.AdminOnlySDDL)
	previous := windowsStandaloneHookRuntimeAncestor
	windowsStandaloneHookRuntimeAncestor = func() (string, error) { return vendor, nil }
	t.Cleanup(func() { windowsStandaloneHookRuntimeAncestor = previous })
}
