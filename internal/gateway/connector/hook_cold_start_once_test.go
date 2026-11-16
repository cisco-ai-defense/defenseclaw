// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// coldStartTestEnv is an account whose gateway is down, with a stand-in
// gateway binary whose start takes startTime and records each launch.
type coldStartTestEnv struct {
	t                         *testing.T
	shell, helper, home, data string
	starts, lock              string
}

func newColdStartTestEnv(t *testing.T, startTime time.Duration) *coldStartTestEnv {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("Windows hooks start the gateway through hookexec")
	}
	env := &coldStartTestEnv{t: t, shell: systemBashForTest(t), helper: materializeHookAssetForTest(t, "hooks/_hardening.sh"), home: t.TempDir()}
	env.data = filepath.Join(env.home, ".defenseclaw")
	env.starts = filepath.Join(env.home, "starts")
	env.lock = filepath.Join(env.data, ".cold-start.lock")
	if err := os.MkdirAll(env.data, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(env.data, "config.yaml"), []byte("gateway: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(env.home, ".local", "bin", "defenseclaw-gateway")
	if err := os.MkdirAll(filepath.Dir(binary), 0o700); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\necho \"$*\" >> " + env.starts + "\nsleep " + strconv.FormatFloat(startTime.Seconds(), 'f', 1, 64) + "\n"
	if err := os.WriteFile(binary, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	// A cold start runs only the helper recorded beside the hook, for the
	// data directory above the hook folder.
	recordGatewayHelperForTest(t, filepath.Join(env.data, "hooks"), binary)
	return env
}

// coldStart runs the hook's cold start; prelude runs after the helper is
// sourced.
func (env *coldStartTestEnv) coldStart(prelude string) {
	command := exec.Command(env.shell, "-c", `source "$0"; `+prelude+` defenseclaw_gateway_cold_start`, env.helper)
	command.Env = append(os.Environ(), "DEFENSECLAW_AGENT_HOME="+env.home, "HOME="+env.home, "DEFENSECLAW_HOME="+env.data, "HOOK_DIR="+filepath.Join(env.data, "hooks"))
	if out, err := command.CombinedOutput(); err != nil {
		env.t.Errorf("cold start: %v\n%s", err, out)
	}
}

// launched counts the starts launched so far, after giving a launch that is
// on its way the time to show.
func (env *coldStartTestEnv) launched(want int) int {
	deadline := time.Now().Add(3 * time.Second)
	for {
		body, _ := os.ReadFile(env.starts)
		n := strings.Count(string(body), "start --hook-cold-start")
		if n >= want || time.Now().After(deadline) {
			time.Sleep(500 * time.Millisecond) // a further start would have written by now
			body, _ = os.ReadFile(env.starts)
			return strings.Count(string(body), "start --hook-cold-start")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func (env *coldStartTestEnv) writeLock(age time.Duration) {
	stamp := strconv.FormatInt(time.Now().Add(-age).Unix(), 10)
	if err := os.WriteFile(env.lock, []byte(stamp+" other.start\n"), 0o600); err != nil {
		env.t.Fatal(err)
	}
}

// GAP-0143: hooks that find the account's gateway down at the same time
// launch one background start, not one each. The start holds the lock until
// it ends, however long its readiness wait (up to 30 s): a hook that comes
// 20 s into it launches nothing. A lock left by a start that died (120 s or
// more old) does not stop the next start.
func TestConcurrentHooksLaunchOneGatewayColdStart(t *testing.T) {
	env := newColdStartTestEnv(t, 2*time.Second)
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			env.coldStart("")
		}()
	}
	wg.Wait()
	if n := env.launched(1); n != 1 {
		t.Fatalf("4 hooks at once launched %d gateway starts, want 1", n)
	}
	env.coldStart("")
	if n := env.launched(2); n != 1 {
		t.Fatalf("a hook during the start launched another: %d starts in all, want 1", n)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Lstat(env.lock); os.IsNotExist(err) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the cold-start lock outlived the start that took it")
		}
		time.Sleep(50 * time.Millisecond)
	}
	env.writeLock(20 * time.Second)
	env.coldStart("")
	if n := env.launched(2); n != 1 {
		t.Fatalf("a hook 20 s into a running start launched another: %d starts in all, want 1", n)
	}
	env.writeLock(130 * time.Second)
	env.coldStart("")
	if n := env.launched(2); n != 2 {
		t.Fatalf("after a start that died, the next hook launched %d starts in all, want 2", n)
	}
}

// Hooks that find a stale lock together replace it once: one start. Each
// removal is slowed, as on a busy host, so every hook has read the stale
// lock before any replaces it.
func TestHooksReplaceAStaleColdStartLockOnce(t *testing.T) {
	env := newColdStartTestEnv(t, time.Second)
	env.writeLock(130 * time.Second)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			env.coldStart(`rm() { sleep 0.3; command rm "$@"; };`)
		}()
	}
	wg.Wait()
	if n := env.launched(1); n != 1 {
		t.Fatalf("8 hooks that found a stale lock launched %d gateway starts, want 1", n)
	}
}
