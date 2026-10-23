// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// shellHookBlocksNatively reports whether the agent a rendered hook answers
// stops the call. Copilot CLI, Hermes and Antigravity act only on a
// structured deny or block on stdout; Cursor denies on any non-zero exit;
// Claude Code, Codex, Devin, Kiro (and the inspect hooks, which Claude Code
// runs) block only on exit 2 or a structured deny, and run the tool on any
// other failed exit.
func shellHookBlocksNatively(script string, code int, stdout string) bool {
	structured := strings.Contains(stdout, `"deny"`) || strings.Contains(stdout, `"block"`) ||
		strings.Contains(stdout, `"continue":false`)
	switch script {
	case "copilot-hook.sh", "hermes-hook.sh", "antigravity-hook.sh":
		return structured
	case "cursor-hook.sh":
		return code != 0 || structured
	}
	return code == 2 || structured
}

// renderPerUserShellHooks renders tc's per-user hooks into data/hooks in
// failMode and returns the hook directory.
func renderPerUserShellHooks(t *testing.T, tc installInFlightShellCase, data, failMode string) string {
	t.Helper()
	hooks := filepath.Join(data, "hooks")
	addr := freeAPIAddr(t)
	if tc.conn.Name() == "cursor" {
		// Cursor's connector setup renders its action hook closed in every
		// mode; the open render is the one an observe install runs.
		if err := writeHookScriptsCommonWithFailMode(hooks, addr, "test-token", failMode, []string{"cursor-hook.sh"}); err != nil {
			t.Fatal(err)
		}
		return hooks
	}
	opts := SetupOpts{DataDir: data, APIAddr: addr, APIToken: "test-token", HookFailMode: failMode, GuardrailMode: "action", WorkspaceDir: data}
	if err := WriteHookScriptsForConnectorObjectWithOpts(hooks, opts, tc.conn); err != nil {
		t.Fatal(err)
	}
	return hooks
}

// runPerUserShellHookAt runs the rendered hook at path with data as the
// account's home and data directory.
func runPerUserShellHookAt(t *testing.T, tc installInFlightShellCase, data, path string) (int, string, string) {
	t.Helper()
	cmd := exec.Command("bash", append([]string{path}, tc.invoke.args...)...)
	cmd.Env = append(sanitizedTestEnv(), "HOME="+data, "DEFENSECLAW_HOME="+data, "DEFENSECLAW_HOOK_MAX_BODY=4096")
	cmd.Env = append(cmd.Env, tc.invoke.env...)
	cmd.Stdin = strings.NewReader(tc.invoke.stdin)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	code := 0
	if err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("run %s: %v", path, err)
		}
		code = exitErr.ExitCode()
	}
	return code, stdout.String(), stderr.String()
}

// GAP-0914 and its class: a rendered per-user shell hook that failed before
// its helpers loaded answered with the mode it was rendered with, and in
// fail mode open let the call run during an install or upgrade. Copilot's
// bootstrap fallback exited 0 with no native deny; Hermes and Antigravity
// exited with a status their agents ignore; Claude Code, Codex, Devin and
// Kiro exited 1, which their agents treat as a hook error that lets the
// tool run. Every shell hook form now reads the one install check
// (defenseclaw_install_lock_held) when such a failure answers: a missing,
// unreadable or failing _hardening.sh (a hook path that does not resolve
// answers through the same exit). Each
// failure blocks while the installer holds the data directory and in fail
// mode closed; fail mode open without an install keeps its answer.
func TestPerUserShellHookBootstrapFailureClosesDuringAnInstall(t *testing.T) {
	failures := []struct {
		name string
		// broken breaks the rendered hooks and returns the path to run.
		broken func(t *testing.T, hooks, script string) string
		// openRuns: fail mode open lets the call run without an install.
		openRuns bool
	}{
		{"the hardening helper is missing", func(t *testing.T, hooks, script string) string {
			if err := os.Remove(filepath.Join(hooks, "_hardening.sh")); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(hooks, script)
		}, true},
		{"the hardening helper fails", func(t *testing.T, hooks, script string) string {
			if err := os.WriteFile(filepath.Join(hooks, "_hardening.sh"), []byte("return 3\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(hooks, script)
		}, true},
		{"the hardening helper cannot be read", func(t *testing.T, hooks, script string) string {
			if os.Geteuid() == 0 {
				t.Skip("root reads every file")
			}
			if err := os.Chmod(filepath.Join(hooks, "_hardening.sh"), 0); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(hooks, script)
		}, true},
	}
	for _, tc := range installInFlightShellCases(t) {
		// The inspect hooks serve every connector: their installed mode is
		// the sidecar the helpers read, so they close in every mode, and so
		// does any non-zero exit of Cursor's.
		closedAnyway := tc.invoke.script == "cursor-hook.sh" || strings.HasPrefix(tc.invoke.script, "inspect-")
		for _, failure := range failures {
			t.Run(tc.name+"/"+tc.invoke.script+"/"+failure.name, func(t *testing.T) {
				t.Parallel()
				answer := func(failMode string, install bool) (bool, string) {
					data := t.TempDir()
					hooks := renderPerUserShellHooks(t, tc, data, failMode)
					path := failure.broken(t, hooks, tc.invoke.script)
					if install {
						if err := os.Mkdir(filepath.Join(data, ".install.lock"), 0o700); err != nil {
							t.Fatal(err)
						}
					}
					code, stdout, stderr := runPerUserShellHookAt(t, tc, data, path)
					return shellHookBlocksNatively(tc.invoke.script, code, stdout),
						fmt.Sprintf("exit %d stdout %q stderr %q", code, stdout, stderr)
				}
				if blocks, got := answer("open", true); !blocks {
					t.Fatalf("fail mode open during an install: %s, want a block", got)
				}
				if blocks, got := answer("closed", false); !blocks {
					t.Fatalf("fail mode closed: %s, want a block", got)
				}
				if failure.openRuns && !closedAnyway {
					// A per-user hook is closed whatever mode it was set up
					// with (sa-port-peer), so open without an install blocks too.
					if blocks, got := answer("open", false); !blocks {
						t.Fatalf("fail mode open without an install: %s, want a block", got)
					}
				}
			})
		}
	}
}

// shellInstallLockCheck is the one install check of the shell hooks, as
// _hardening.sh defines it.
func shellInstallLockCheck(t *testing.T) string {
	t.Helper()
	hardening, err := hookFS.ReadFile("hooks/_hardening.sh")
	if err != nil {
		t.Fatal(err)
	}
	text := string(hardening)
	start := strings.Index(text, "# defenseclaw_install_lock_held DATA")
	if start < 0 {
		t.Fatal("_hardening.sh defines no defenseclaw_install_lock_held")
	}
	end := strings.Index(text[start:], "\n}\n")
	if end < 0 {
		t.Fatal("defenseclaw_install_lock_held has no end")
	}
	return text[start : start+end+3]
}

// Every rendered per-user shell hook carries the same install check as
// _hardening.sh, before its helpers load, and reads .install.lock only
// through it; the check holds the lock by the rule the native hook, the
// in-agent plugins and the Windows adapters use: the lock exists as any
// file type, or the data directory exists but cannot be searched, or there
// is no data directory to look in.
func TestShellHooksShareTheOneInstallCheck(t *testing.T) {
	check := shellInstallLockCheck(t)
	seen := map[string]bool{}
	for _, tc := range installInFlightShellCases(t) {
		if seen[tc.invoke.script] {
			continue
		}
		seen[tc.invoke.script] = true
		hooks := renderPerUserShellHooks(t, tc, t.TempDir(), "open")
		body, err := os.ReadFile(filepath.Join(hooks, tc.invoke.script))
		if err != nil {
			t.Fatal(err)
		}
		text := string(body)
		if !strings.Contains(text, check) {
			t.Errorf("%s does not carry the shared install check", tc.invoke.script)
			continue
		}
		if got, want := strings.Count(text, ".install.lock"), strings.Count(check, ".install.lock"); got != want {
			t.Errorf("%s reads .install.lock %d times, want only through the shared check (%d)", tc.invoke.script, got, want)
		}
		if strings.Index(text, check) > strings.Index(text, `"${HOOK_DIR}/_hardening.sh"`) {
			t.Errorf("%s defines the install check after it loads its helpers", tc.invoke.script)
		}
	}
	for _, script := range []string{"inspect-tool.sh", "inspect-request.sh", "inspect-response.sh", "inspect-tool-response.sh"} {
		if !seen[script] {
			t.Errorf("no case covers %s", script)
		}
	}

	root := t.TempDir()
	mk := func(name string, make func(path string) error) string {
		path := filepath.Join(root, name)
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
		if make != nil {
			if err := make(filepath.Join(path, ".install.lock")); err != nil {
				t.Fatal(err)
			}
		}
		return path
	}
	file := filepath.Join(root, "a-file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	unsearchable := mk("unsearchable", nil)
	if err := os.Chmod(unsearchable, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(unsearchable, 0o700) })
	rows := []struct {
		name string
		data string
		held bool
	}{
		{"no data directory to look in", "", true},
		{"the data directory does not exist", filepath.Join(root, "missing"), false},
		{"no lock", mk("free", nil), false},
		{"the lock is a directory", mk("lock-dir", func(p string) error { return os.Mkdir(p, 0o700) }), true},
		{"the lock is a file", mk("lock-file", func(p string) error { return os.WriteFile(p, nil, 0o600) }), true},
		{"the lock is a dangling link", mk("lock-link", func(p string) error { return os.Symlink(filepath.Join(root, "nowhere"), p) }), true},
		{"the data directory is a file", file, true},
	}
	if os.Geteuid() != 0 {
		rows = append(rows, struct {
			name string
			data string
			held bool
		}{"the data directory cannot be searched", unsearchable, true})
	}
	for _, row := range rows {
		out, err := exec.Command("bash", "-c", "set -euo pipefail\n"+check+`if defenseclaw_install_lock_held "$1"; then echo held; else echo free; fi`, "check", row.data).CombinedOutput()
		if err != nil {
			t.Fatalf("%s: %v: %s", row.name, err, out)
		}
		if got := strings.TrimSpace(string(out)) == "held"; got != row.held {
			t.Errorf("%s: held=%v, want %v (%s)", row.name, got, row.held, out)
		}
	}
}

// The installers close a per-user hook whose mode they close
// (RefreshHookFailModes): the bootstrap mode is closed with the rest.
func TestRefreshHookFailModesClosesTheBootstrapMode(t *testing.T) {
	for _, tc := range installInFlightShellCases(t) {
		if !strings.HasSuffix(tc.invoke.script, "-hook.sh") {
			continue
		}
		hooks := renderPerUserShellHooks(t, tc, t.TempDir(), "open")
		if _, err := RefreshHookFailModes(hooks, func(string) string { return "closed" }); err != nil {
			t.Fatal(err)
		}
		body, err := os.ReadFile(filepath.Join(hooks, tc.invoke.script))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(body), `_DC_BOOT_FAIL_MODE="open"`) {
			t.Errorf("%s keeps its open bootstrap mode after the refresh", tc.invoke.script)
		}
	}
}
