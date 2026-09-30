// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gitsafe

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func envValue(env []string, key string) (string, bool) {
	for _, e := range env {
		if k, v, ok := strings.Cut(e, "="); ok && k == key {
			return v, true
		}
	}
	return "", false
}

func TestCommandScrubsEnvironmentAndPrependsFlags(t *testing.T) {
	t.Setenv("GIT_DIR", "/attacker")
	t.Setenv("GIT_CONFIG_PARAMETERS", "'core.fsmonitor=evil'")
	t.Setenv("XDG_CONFIG_HOME", "/attacker/xdg")
	cmd, cleanup, err := Command(context.Background(), t.TempDir(), "status")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if _, ok := envValue(cmd.Env, "GIT_DIR"); ok {
		t.Fatal("GIT_DIR leaked into the child")
	}
	if _, ok := envValue(cmd.Env, "GIT_CONFIG_PARAMETERS"); ok {
		t.Fatal("GIT_CONFIG_PARAMETERS leaked into the child")
	}
	for key, want := range map[string]string{"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_TERMINAL_PROMPT": "0"} {
		if got, _ := envValue(cmd.Env, key); got != want {
			t.Fatalf("%s = %q, want %q", key, got, want)
		}
	}
	home, _ := envValue(cmd.Env, "HOME")
	if xdg, _ := envValue(cmd.Env, "XDG_CONFIG_HOME"); xdg != home || home == "" {
		t.Fatalf("HOME=%q XDG_CONFIG_HOME=%q, want the same private temp dir", home, xdg)
	}
	args := strings.Join(cmd.Args, " ")
	for _, flag := range []string{"core.fsmonitor=false", "core.hooksPath=/dev/null", "core.alternateRefsCommand=", "remote.ext.uploadpack=", "--no-optional-locks"} {
		if !strings.Contains(args, flag) {
			t.Fatalf("args %q missing %s", args, flag)
		}
	}
	if cmd.Args[len(cmd.Args)-1] != "status" {
		t.Fatalf("subcommand not last: %v", cmd.Args)
	}
}

func TestCommandRejectsEmptyInput(t *testing.T) {
	if _, _, err := Command(context.Background(), "", "status"); err == nil {
		t.Fatal("empty dir accepted")
	}
	if _, _, err := Command(context.Background(), t.TempDir()); err == nil {
		t.Fatal("empty args accepted")
	}
}

// privateTempDir points os.TempDir at a new empty directory for the test.
func privateTempDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("TMPDIR", dir) // Unix
	t.Setenv("TMP", dir)    // Windows: GetTempPath reads TMP, then TEMP
	t.Setenv("TEMP", dir)
	if got := filepath.Clean(os.TempDir()); got != filepath.Clean(dir) {
		t.Skipf("os.TempDir() = %q, not the test's %q", got, dir)
	}
	return dir
}

func leftovers(t *testing.T, dir string) []string {
	t.Helper()
	left, err := filepath.Glob(filepath.Join(dir, "defenseclaw-gitsafe-home-*"))
	if err != nil {
		t.Fatal(err)
	}
	return left
}

// TMP-RT-1: every CLI process that ran git left an empty
// defenseclaw-gitsafe-home-* directory in TMPDIR, which no housekeeping
// empties when the user set it. Each command's HOME is its own, and the
// cleanup removes it.
func TestCommandHomeIsRemovedByItsCleanup(t *testing.T) {
	tmp := privateTempDir(t)
	cmd, cleanup, err := Command(context.Background(), t.TempDir(), "status")
	if err != nil {
		t.Fatal(err)
	}
	home, _ := envValue(cmd.Env, "HOME")
	if filepath.Dir(home) != filepath.Clean(tmp) || !strings.HasPrefix(filepath.Base(home), "defenseclaw-gitsafe-home-") {
		t.Fatalf("HOME = %q, want a defenseclaw-gitsafe-home-* directory in %q", home, tmp)
	}
	if fi, err := os.Stat(home); err != nil || !fi.IsDir() {
		t.Fatalf("HOME %q before the cleanup: %v", home, err)
	}
	// Whatever git wrote there goes too.
	if err := os.WriteFile(filepath.Join(home, ".gitconfig.lock"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	cleanup()
	cleanup() // a second call is harmless
	if left := leftovers(t, tmp); len(left) != 0 {
		t.Fatalf("left in TMPDIR after the cleanup: %v", left)
	}
}

func TestGitRunLeavesNothingInTMPDIR(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	tmp := privateTempDir(t)
	repo := t.TempDir()
	for _, args := range [][]string{{"init", "-q"}, {"status", "--porcelain"}} {
		cmd, cleanup, err := Command(context.Background(), repo, args...)
		if err != nil {
			t.Fatal(err)
		}
		out, err := cmd.CombinedOutput()
		cleanup()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	if left := leftovers(t, tmp); len(left) != 0 {
		t.Fatalf("left in TMPDIR after git ran: %v", left)
	}
}

func TestConcurrentCommandsGetTheirOwnHome(t *testing.T) {
	tmp := privateTempDir(t)
	var wg sync.WaitGroup
	homes := make([]string, 16)
	cleanups := make([]func(), len(homes))
	for i := range homes {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			cmd, cleanup, err := Command(context.Background(), tmp, "status")
			if err != nil {
				t.Error(err)
				return
			}
			homes[i], _ = envValue(cmd.Env, "HOME")
			cleanups[i] = cleanup
		}(i)
	}
	wg.Wait()
	seen := map[string]bool{}
	for _, h := range homes {
		if h == "" || seen[h] {
			t.Fatalf("homes not distinct: %v", homes)
		}
		seen[h] = true
	}
	// One command's cleanup leaves the others' HOME in place.
	cleanups[0]()
	if _, err := os.Stat(homes[1]); err != nil {
		t.Fatalf("another command's HOME went with the first's cleanup: %v", err)
	}
	for _, c := range cleanups[1:] {
		c()
	}
	if left := leftovers(t, tmp); len(left) != 0 {
		t.Fatalf("left in TMPDIR: %v", left)
	}
}
