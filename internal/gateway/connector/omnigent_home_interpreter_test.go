// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// omnigentUVToolLayout builds the layout `uv tool install omnigent` leaves
// under a home: ~/.local/bin/omnigent, whose shebang names the tool
// environment's python, a link to uv's managed CPython.
func omnigentUVToolLayout(t *testing.T, home, purelib string) (interpreterDir string) {
	t.Helper()
	interpreterDir = filepath.Join(home, ".local", "share", "uv", "python", "cpython-3.12.14-test", "bin")
	toolBin := filepath.Join(home, ".local", "share", "uv", "tools", "omnigent", "bin")
	userBin := filepath.Join(home, ".local", "bin")
	for _, dir := range []string{interpreterDir, toolBin, userBin} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	interpreter := filepath.Join(interpreterDir, "python3.12")
	body := "#!/bin/sh\nprintf '0.15.0\\n%s\\n' '" + purelib + "'\n"
	if err := os.WriteFile(interpreter, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	toolPython := filepath.Join(toolBin, "python")
	if err := os.Symlink(interpreter, toolPython); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(toolBin, "omnigent"), []byte("#!"+toolPython+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(toolBin, "omnigent"), filepath.Join(userBin, "omnigent")); err != nil {
		t.Fatal(err)
	}
	return interpreterDir
}

// The standalone guardian applies OmniGent in a worker that runs as the
// target user. An interpreter `uv tool install` placed under that user's
// home, which only the user can change, is admitted there; a group- or
// other-writable directory on the way is refused with the command to fix
// it. Per-user installs keep the DEFENSECLAW_TRUSTED_BIN_PREFIXES rule.
func TestOmnigentManagedAdmitsAnOwnerOnlyInterpreterUnderTheUsersHome(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("a home interpreter is never admitted as root")
	}
	home := t.TempDir()
	if err := os.Chmod(home, 0o700); err != nil {
		t.Fatal(err)
	}
	purelib := filepath.Join(home, ".local", "share", "uv", "tools", "omnigent", "lib", "python3.12", "site-packages")
	interpreterDir := omnigentUVToolLayout(t, home, purelib)
	t.Setenv("HOME", home)
	t.Setenv("PATH", filepath.Join(home, ".local", "bin"))
	t.Setenv("DEFENSECLAW_TRUSTED_BIN_PREFIXES", "")
	previous := OmnigentSitePackagesPathOverride
	OmnigentSitePackagesPathOverride = ""
	t.Cleanup(func() { OmnigentSitePackagesPathOverride = previous })

	managed := SetupOpts{ManagedEnterprise: true}
	got, err := omnigentSitePackages(context.Background(), managed)
	if err != nil {
		t.Fatalf("managed: an owner-only uv interpreter under the home must be admitted: %v", err)
	}
	if got != purelib {
		t.Fatalf("site-packages = %q, want %q", got, purelib)
	}

	if _, err := omnigentSitePackages(context.Background(), SetupOpts{}); err == nil ||
		!strings.Contains(err.Error(), "DEFENSECLAW_TRUSTED_BIN_PREFIXES") {
		t.Fatalf("per-user: error = %v, want the unchanged trusted-prefix refusal", err)
	}

	pythonRoot := filepath.Dir(filepath.Dir(interpreterDir))
	if err := os.Chmod(pythonRoot, 0o775); err != nil {
		t.Fatal(err)
	}
	_, err = omnigentSitePackages(context.Background(), managed)
	if err == nil || !strings.Contains(err.Error(), "writable by group or others (chmod go-w)") || strings.Contains(err.Error(), "DEFENSECLAW_TRUSTED_BIN_PREFIXES") {
		t.Fatalf("managed: a group-writable directory must be refused with the fix: %v", err)
	}
	if err := os.Chmod(pythonRoot, 0o755); err != nil {
		t.Fatal(err)
	}

	// The tool environment's link must be the user's as well.
	toolBin := filepath.Join(home, ".local", "share", "uv", "tools", "omnigent", "bin")
	if err := os.Chmod(toolBin, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := omnigentSitePackages(context.Background(), managed); err == nil || !strings.Contains(err.Error(), "writable by group or others") {
		t.Fatalf("managed: a writable tool environment must be refused: %v", err)
	}
}

// An interpreter outside the home and every trusted prefix is refused for a
// managed install with the administrator setting, not an environment
// variable the guardian's users cannot set.
func TestOmnigentManagedRefusalNamesTheAdministratorSetting(t *testing.T) {
	home := t.TempDir()
	elsewhere := t.TempDir()
	binDir := filepath.Join(elsewhere, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"omnigent", "python"} {
		if err := os.WriteFile(filepath.Join(binDir, name), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	t.Setenv("PATH", binDir)
	t.Setenv("DEFENSECLAW_TRUSTED_BIN_PREFIXES", "")
	previous := OmnigentSitePackagesPathOverride
	OmnigentSitePackagesPathOverride = ""
	t.Cleanup(func() { OmnigentSitePackagesPathOverride = previous })

	_, err := omnigentSitePackages(context.Background(), SetupOpts{ManagedEnterprise: true})
	if err == nil || !strings.Contains(err.Error(), "enterprise.enrollment.agent_prefixes") ||
		strings.Contains(err.Error(), "DEFENSECLAW_TRUSTED_BIN_PREFIXES") {
		t.Fatalf("managed refusal = %v, want the administrator setting", err)
	}
}
