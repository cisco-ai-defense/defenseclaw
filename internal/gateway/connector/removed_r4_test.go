// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

// until 1.1: regression tests for the retired connector cleanup and deny
// stub. Delete with removed.go.

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// A caller can invoke a restored hook as `bash script`, bypassing the
// shebang's -p. Bash then imports functions and reads BASH_ENV. The deny
// verdict and exit status must survive both ways to define shell functions.
func TestRemovedOpenHandsStubBlocksImportedBashFunctions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the retired shell hook ran only on Unix")
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skipf("bash is unavailable: %v", err)
	}
	h := newRemovedHost(t)
	h.stage(t, removedOpenHands)
	if err := removedOpenHands.Teardown(context.Background(), h.opts); err != nil {
		t.Fatal(err)
	}
	startup := filepath.Join(h.home, "startup.sh")
	writeRemovedFile(t, startup, "exit() { return 0; }\necho() { printf '%s\\n' '{\"decision\":\"allow\"}'; }\ncommand() { return 0; }\n", 0o600)
	for _, tc := range []struct {
		name string
		env  []string
	}{
		{"imported functions", []string{
			"BASH_FUNC_exit%%=() { return 0; }",
			"BASH_FUNC_echo%%=() { printf '%s\\n' '{\"decision\":\"allow\"}'; }",
			"BASH_FUNC_command%%=() { return 0; }",
		}},
		{"startup functions", []string{"BASH_ENV=" + startup}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command(bash, h.script(removedOpenHands))
			cmd.Env = append([]string{"HOME=" + h.home, "PATH=/usr/bin:/bin", "LC_ALL=C"}, tc.env...)
			out, err := cmd.Output()
			var failed *exec.ExitError
			if !errors.As(err, &failed) || failed.ExitCode() != 2 ||
				!strings.Contains(string(out), `"decision":"deny"`) || strings.Contains(string(out), `"decision":"allow"`) {
				t.Fatalf("bash hook exit=%v, stdout=%q; want only the deny verdict and exit 2", err, out)
			}
		})
	}
}

// A running old Bash hook can resume past the new stub in a longer hard-linked
// file. Its final tail must also fail closed if the process already imported
// function overrides before teardown rewrote the file.
func TestRemovedOpenHandsInPlaceTailCannotReturnSuccess(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the retired shell hook ran only on Unix")
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skipf("bash is unavailable: %v", err)
	}
	cmd := exec.Command(bash, "-c", removedOpenHands.inPlaceTail)
	cmd.Env = []string{
		"PATH=/usr/bin:/bin",
		"BASH_FUNC_exit%%=() { return 0; }",
		"BASH_FUNC_command%%=() { return 0; }",
	}
	if err := cmd.Run(); err == nil {
		t.Fatal("the in-place deny tail returned success with imported Bash functions")
	} else if failed, ok := err.(*exec.ExitError); !ok || failed.ExitCode() != 2 {
		t.Fatalf("the in-place deny tail exited with %v, want exit 2", err)
	}
}

// A late token-path refusal must be found before a script or another token
// changes. This keeps the cleanup retryable as a unit when a token path is
// a directory, a symlink, or an unsafe temporary file.
func TestRemovedTeardownPreflightsEveryTokenBeforeWritingTheStub(t *testing.T) {
	for _, c := range removedConnectorsUnderTest() {
		paths := []struct {
			name string
			path func(string) string
		}{{"OTLP token", c.otlpTokenPath}}
		if !c.keepHookToken {
			paths = append(paths, struct {
				name string
				path func(string) string
			}{"hook token", c.hookTokenPath})
		}
		for _, token := range paths {
			for _, suffix := range []string{"", ".tmp"} {
				for _, kind := range []string{"directory", "symlink"} {
					t.Run(c.name+"/"+token.name+suffix+"/"+kind, func(t *testing.T) {
						h := newRemovedHost(t)
						h.stage(t, c)
						blocked := token.path(h.dataDir) + suffix
						if suffix == "" {
							if err := os.Remove(blocked); err != nil {
								t.Fatal(err)
							}
						}
						if kind == "directory" {
							writeRemovedFile(t, filepath.Join(blocked, "keep"), "user data\n", 0o600)
						} else {
							target := filepath.Join(h.home, "user-token")
							writeRemovedFile(t, target, "user data\n", 0o600)
							if err := os.Symlink(target, blocked); err != nil {
								t.Skipf("symlink unavailable: %v", err)
							}
						}
						before := h.snapshot(t)
						if err := c.Teardown(context.Background(), h.opts); err == nil {
							t.Fatalf("Teardown accepted a %s at a token path", kind)
						}
						requireRemovedSame(t, "refused teardown", h.snapshot(t), before)
						if err := os.RemoveAll(blocked); err != nil {
							t.Fatal(err)
						}
						if err := c.Teardown(context.Background(), h.opts); err != nil {
							t.Fatalf("retry after removing the unsafe token path: %v", err)
						}
						h.requireStub(t, c)
					})
				}
			}
		}
	}
}

// An edited hooks.json is left for manual cleanup, but an older exit-zero
// tombstone it still invokes must become the deny stub on this pass.
func TestRemovedOpenHandsEditedConfigStillReplacesLegacyAllowTombstone(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the retired shell tombstone ran only on Unix")
	}
	h := newRemovedHost(t)
	h.stage(t, removedOpenHands)
	config := `{"pre_tool_use":[{"hooks":[{"command":"` + h.script(removedOpenHands) + `"},{"command":"/usr/local/bin/operator-hook"}]}]}`
	writeRemovedFile(t, h.agentConfig, config, 0o600)
	writeRemovedFile(t, h.script(removedOpenHands), disabledHookTombstone("OpenHands"), 0o700)
	if err := removedOpenHands.Teardown(context.Background(), h.opts); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(h.agentConfig); err != nil || string(got) != config {
		t.Fatalf("edited hooks.json = %q, %v; want the operator entries preserved", got, err)
	}
	leftovers, _ := RemovedConnectorLeftovers(removedOpenHandsID, h.opts)
	if !removedListsPath(leftovers, h.agentConfig) {
		t.Fatalf("manual cleanup did not name the edited hooks.json: %+v", leftovers)
	}
	requireRemovedHookBlocks(t, h.script(removedOpenHands))
}
