// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// renderPerUserAdapterInDataDir renders a per-user Windows adapter in
// failMode into data\hooks, where setup writes it, and returns its path.
func renderPerUserAdapterInDataDir(t *testing.T, adapter, hookPath, failMode, data string) string {
	t.Helper()
	hooks := filepath.Join(data, "hooks")
	if err := os.MkdirAll(hooks, 0o700); err != nil {
		t.Fatal(err)
	}
	var body []byte
	switch adapter {
	case "copilot-hook.ps1":
		tmpl, err := hookFS.ReadFile("hooks/copilot-hook.ps1")
		if err != nil {
			t.Fatal(err)
		}
		rendered, err := renderTemplate(string(tmpl), templateData{
			FailMode:             failMode,
			HookBinaryPS:         strings.ReplaceAll(hookPath, "'", "''"),
			CopilotHookTimeoutMS: 10_000,
		})
		if err != nil {
			t.Fatal(err)
		}
		body = []byte(rendered)
	case "cursor-hook.ps1":
		rendered, err := renderWindowsCursorAdapter(hookPath, failMode, false, 10_000)
		if err != nil {
			t.Fatal(err)
		}
		body = rendered
	default:
		t.Fatalf("unknown adapter %s", adapter)
	}
	path := filepath.Join(hooks, adapter)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// GAP-0915: a per-user Windows adapter rendered open answered every
// failure of its hook launcher (missing, crashed, timed out) from its open
// catch block, and so allowed the call while this account's installer held
// its data directory: the native hook a launcher runs checks the install
// itself, but an adapter whose launcher never answered did not. Both
// adapters now read the shared install check in that catch block: during
// an install (the lock as a directory, as install.ps1 takes it, or any
// other file type) the call gets the adapter's closed answer, as in fail
// mode closed. Without an install the open choice still lets the call run,
// and the installers' closing refresh (RefreshHookFailModes) still closes
// the adapter.
func TestPerUserWindowsAdaptersCloseDuringAnInstall(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	launchers := []struct {
		name string
		path string
		mode string // TEST_COPILOT_ADAPTER_MODE of the helper launcher
	}{
		{"the hook launcher is missing", filepath.Join(t.TempDir(), "defenseclaw-hook.exe"), ""},
		{"the hook launcher crashes", executable, "crash"},
	}
	locks := []struct {
		name string
		take func(path string) error
	}{
		{"the install lock is a directory", func(path string) error { return os.Mkdir(path, 0o700) }},
		{"the install lock is a file", func(path string) error { return os.WriteFile(path, nil, 0o600) }},
	}
	for _, adapter := range []string{"copilot-hook.ps1", "cursor-hook.ps1"} {
		for _, launcher := range launchers {
			t.Run(adapter+"/"+launcher.name, func(t *testing.T) {
				if launcher.mode != "" {
					t.Setenv(copilotAdapterHelperMode, launcher.mode)
				}
				run := func(path string) (string, string, int) {
					if adapter == "copilot-hook.ps1" {
						return runCopilotAdapterTest(t, path, `{"source":"copilot-adapter-probe"}`)
					}
					return runCursorAdapterTest(t, path, `{"source":"cursor-adapter-probe"}`)
				}
				denied := func(stdout string, code int) bool {
					if adapter == "copilot-hook.ps1" {
						return code == 0 && strings.TrimSpace(stdout) == copilotAdapterClosedDenial
					}
					return code != 0 && strings.Contains(stdout, `"permission":"deny"`)
				}
				allowed := func(stdout string, code int) bool {
					if adapter == "copilot-hook.ps1" {
						return code == 0 && strings.TrimSpace(stdout) == ""
					}
					return code == 0 && strings.Contains(stdout, `"continue":true`)
				}

				data := t.TempDir()
				path := renderPerUserAdapterInDataDir(t, adapter, launcher.path, "open", data)
				if stdout, stderr, code := run(path); !allowed(stdout, code) {
					t.Fatalf("fail mode open without an install: exit %d stdout %q stderr %q, want the call to run", code, stdout, stderr)
				}
				for _, lock := range locks {
					lockPath := filepath.Join(data, ".install.lock")
					if err := lock.take(lockPath); err != nil {
						t.Fatal(err)
					}
					stdout, stderr, code := run(path)
					if !denied(stdout, code) {
						t.Fatalf("%s, fail mode open: exit %d stdout %q stderr %q, want the closed answer", lock.name, code, stdout, stderr)
					}
					if !strings.Contains(stderr, "being installed or upgraded") {
						t.Fatalf("%s: stderr %q does not name the install", lock.name, stderr)
					}
					if err := os.RemoveAll(lockPath); err != nil {
						t.Fatal(err)
					}
				}

				closed := renderPerUserAdapterInDataDir(t, adapter, launcher.path, "closed", t.TempDir())
				if stdout, stderr, code := run(closed); !denied(stdout, code) {
					t.Fatalf("fail mode closed: exit %d stdout %q stderr %q, want the closed answer", code, stdout, stderr)
				}

				if _, err := RefreshHookFailModes(filepath.Dir(path), func(string) string { return "closed" }); err != nil {
					t.Fatal(err)
				}
				if stdout, stderr, code := run(path); !denied(stdout, code) {
					t.Fatalf("the refreshed open adapter: exit %d stdout %q stderr %q, want the closed answer", code, stdout, stderr)
				}
			})
		}
	}
}
