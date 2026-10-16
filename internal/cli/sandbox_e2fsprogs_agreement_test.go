// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterpriseunix"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// The administrator's ensure result, the real gateway exec plan and the
// managed doctor's row must identify the same usable tool directory, or all
// refuse. The test runs on Linux using the macOS plan and a rooted fixture.
func TestManagedMacE2fsprogsEnsureGatewayDoctorAgree(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("the managed gateway exec shim refuses root")
	}
	root := testenv.TraversableTempDir(t)
	home, configDir := filepath.Join(root, "home"), filepath.Join(root, "etc")
	if err := os.MkdirAll(filepath.Join(configDir, "openshell"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	adminBinary := filepath.Join(root, "openshell-gateway")
	if err := os.WriteFile(adminBinary, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	priorHost, priorHome, priorFile, priorDir := sandboxDaemonHost, openShellExecHome, openShellExecTrustedFile, openShellExecTrustedDir
	priorSettings, priorAdmin, priorEnv, priorTelemetry, priorDocker := openShellExecSettings, openShellExecAdminBinary,
		openShellExecRenderedEnv, openShellExecUpstreamTelemetry, openShellExecDockerContext
	t.Cleanup(func() {
		sandboxDaemonHost, openShellExecHome, openShellExecTrustedFile, openShellExecTrustedDir = priorHost, priorHome, priorFile, priorDir
		openShellExecSettings, openShellExecAdminBinary, openShellExecRenderedEnv, openShellExecUpstreamTelemetry, openShellExecDockerContext =
			priorSettings, priorAdmin, priorEnv, priorTelemetry, priorDocker
	})
	sandboxDaemonHost = func(string) (managed.StandaloneLayout, *managed.RuntimeDescriptor, error) {
		return managed.StandaloneLayout{ConfigDir: configDir}, &managed.RuntimeDescriptor{}, nil
	}
	openShellExecHome = func() (string, error) { return home, nil }
	openShellExecAdminBinary = func(_, _ string, trusted func(string) error) (string, error) {
		return adminBinary, trusted(adminBinary)
	}
	openShellExecRenderedEnv = func(string) ([]string, error) { return nil, nil }
	openShellExecUpstreamTelemetry = func(context.Context) bool { return false }
	openShellExecDockerContext = func(context.Context) (string, error) { return "", nil }
	adminDir, untrusted := "", false
	openShellExecSettings = func(context.Context) sandboxrelay.EnterpriseOpenShell {
		return sandboxrelay.EnterpriseOpenShell{Install: config.EnterpriseOpenShellInstallPrerequisite, E2fsprogsDir: adminDir}
	}
	trustedFile := func(path, _ string) error {
		if untrusted && strings.HasPrefix(path, adminDir+string(filepath.Separator)) {
			return errors.New("an account can change the tool")
		}
		return nil
	}
	trustedDir := func(path, _ string) error {
		if untrusted && strings.HasPrefix(path, adminDir) {
			return errors.New("an account can change the directory")
		}
		return nil
	}
	openShellExecTrustedFile, openShellExecTrustedDir = trustedFile, trustedDir
	ensure := &enterpriseunix.Env{GOOS: "darwin", Trust: func(_ string, kind enterpriseunix.TrustKind) error {
		if kind != enterpriseunix.TrustRulePack {
			t.Fatalf("ensure checked trust kind %v", kind)
		}
		if untrusted {
			return errors.New("an account can change the directory")
		}
		return nil
	}}
	writeTool := func(dir, name string) {
		t.Helper()
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte("tool"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	type testCase struct {
		name, form string
		write      []string
		want       string
		untrusted  bool
		private    bool
		ownBuild   bool
	}
	cases := []testCase{
		{name: "install prefix", form: "prefix", write: []string{"sbin/mke2fs", "sbin/debugfs"}, want: "sbin"},
		{name: "tool folder", form: "sbin", write: []string{"sbin/mke2fs", "sbin/debugfs"}, want: "sbin"},
		{name: "only one tool", form: "prefix", write: []string{"sbin/mke2fs"}},
		{name: "tools split across folders", form: "prefix", write: []string{"sbin/mke2fs", "bin/debugfs"}},
		{name: "untrusted folder", form: "prefix", write: []string{"sbin/mke2fs", "sbin/debugfs"}, untrusted: true},
		{name: "private tool folder", form: "prefix", write: []string{"sbin/mke2fs", "sbin/debugfs"}, private: true},
		{name: "private unused sibling", form: "prefix", write: []string{"bin/mke2fs", "bin/debugfs"}, private: true},
		{name: "bad admin setting with an account build", form: "prefix", write: []string{"sbin/mke2fs"}, ownBuild: true},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			prefix := filepath.Join(root, "case-"+string(rune('a'+i)))
			for _, tool := range tc.write {
				writeTool(filepath.Join(prefix, filepath.Dir(tool)), filepath.Base(tool))
			}
			if tc.ownBuild {
				own := filepath.Join(home, ".local", "opt", "e2fsprogs", "sbin")
				writeTool(own, "mke2fs")
				writeTool(own, "debugfs")
			}
			adminDir, untrusted = prefix, tc.untrusted
			if tc.form == "sbin" {
				adminDir = filepath.Join(prefix, "sbin")
			}
			if tc.private {
				if err := os.MkdirAll(filepath.Join(prefix, "sbin"), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(filepath.Join(prefix, "sbin"), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			result := ensure.CheckE2fsprogsDir(adminDir)
			plan, planErr := planSandboxOpenShellExec(context.Background(), "darwin", nil)
			doctor := (&openshell.Doctor{GOOS: "darwin", Managed: true, AdminE2fsprogsKnown: true, AdminE2fsprogsDir: adminDir,
				HomeDir: func() (string, error) { return home, nil }, TrustedE2fsprogsDir: trustedDir, TrustedE2fsprogsFile: trustedFile}).ManagedE2fsprogsCheck()
			if tc.want != "" {
				want := filepath.Join(prefix, tc.want)
				if result.ToolDir != want || planErr != nil || strings.SplitN(envValue(plan.env, "PATH"), ":", 2)[0] != want ||
					doctor.Status != openshell.StatusPass || !strings.Contains(doctor.Detail, want) {
					t.Fatalf("want all three to use %s: ensure %+v, gateway %v %v, doctor %+v", want, result, planErr, envValue(plan.env, "PATH"), doctor)
				}
				return
			}
			if result.ToolDir != "" || result.Problem == "" || !errors.Is(planErr, errOpenShellPrerequisiteMissing) || doctor.Status != openshell.StatusFail ||
				doctor.Fix == nil || !strings.Contains(doctor.Fix.Summary, "install prefix or the folder") {
				t.Fatalf("want all three to refuse: ensure %+v, gateway %v, doctor %+v", result, planErr, doctor)
			}
			refusedPath := adminDir
			if tc.private {
				refusedPath = filepath.Join(prefix, "sbin")
			}
			if !strings.Contains(result.Problem, refusedPath) || !strings.Contains(planErr.Error(), refusedPath) || !strings.Contains(doctor.Detail, refusedPath) {
				t.Fatalf("refusal did not name %s in all three: ensure %+v, gateway %v, doctor %+v", refusedPath, result, planErr, doctor)
			}
		})
	}
}

// With no administrator setting or account build, a managed gateway and
// doctor both refuse a keg, including one reached through a writable opt
// directory that can retarget its symlink.
func TestManagedMacE2fsprogsGatewayDoctorRefuseKeg(t *testing.T) {
	for _, symlink := range []bool{false, true} {
		name := "trusted-looking keg"
		if symlink {
			name = "symlink in writable opt"
		}
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			home := filepath.Join(root, "home")
			if err := os.MkdirAll(home, 0o755); err != nil {
				t.Fatal(err)
			}
			cellar := filepath.Join(root, "hb", "Cellar", "e2fsprogs", "1.47", "sbin")
			if err := os.MkdirAll(cellar, 0o755); err != nil {
				t.Fatal(err)
			}
			for _, tool := range []string{"mke2fs", "debugfs"} {
				if err := os.WriteFile(filepath.Join(cellar, tool), []byte("#!/bin/sh\n"), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			keg := cellar
			if symlink {
				opt := filepath.Join(root, "hb", "opt")
				if err := os.MkdirAll(opt, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(opt, 0o777); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join("..", "Cellar", "e2fsprogs", "1.47"), filepath.Join(opt, "e2fsprogs")); err != nil {
					t.Fatal(err)
				}
				keg = filepath.Join(opt, "e2fsprogs", "sbin")
			}
			if dir, err := openShellE2fsprogs("", home); dir != "" || !errors.Is(err, errOpenShellPrerequisiteMissing) || strings.Contains(err.Error(), keg) {
				t.Fatalf("gateway used keg: dir=%q err=%v", dir, err)
			}
			doctor := (&openshell.Doctor{GOOS: "darwin", Managed: true, AdminE2fsprogsKnown: true,
				HomeDir: func() (string, error) { return home, nil }, E2fsprogsDirs: []string{keg}}).ManagedE2fsprogsCheck()
			if doctor.Status != openshell.StatusFail || !strings.Contains(doctor.Detail, "Homebrew keg is not used") || strings.Contains(doctor.Detail, keg) {
				t.Fatalf("doctor used keg: %+v", doctor)
			}
		})
	}
}
