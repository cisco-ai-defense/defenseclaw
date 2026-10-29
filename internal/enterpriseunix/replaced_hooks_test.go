// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A standalone manifest may name an account without publishing its UID.
// The guardian resolves that row, so the lifecycle must fence it as well.
func TestReplacedHookTargetsResolveNameOnlyManifestRows(t *testing.T) {
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	uid, err := strconv.Atoi(current.Uid)
	if err != nil || uid <= 0 {
		t.Skip("the fixture needs a non-root account")
	}
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.2")}))
	dataDir := filepath.Join(current.HomeDir, "managed-data")
	writeHostFile(t, h, h.env.Layout.ManifestPath, fmt.Sprintf("version: 1\ntargets:\n  - user: %q\n    data_dir: %q\n    connector: claudecode\n", current.Username, dataDir))
	l := &lifecycle{env: h.env}
	targets := l.replacedHookTargets(t.Context())
	if len(targets) != 1 || targets[0].uid != uid || targets[0].home != current.HomeDir || targets[0].folder() != filepath.Join(dataDir, "hooks") {
		t.Fatalf("name-only targets = %+v, want uid %d and hooks in %s", targets, uid, dataDir)
	}
	if err := os.MkdirAll(h.env.P(current.HomeDir), 0o700); err != nil {
		t.Fatal(err)
	}
	writeReplacedHooks(t, h.env.P(targets[0].folder()), replacedHardening103)
	var stops int
	var stoppedUnfenced bool
	h.services.observe = func(call string) {
		if strings.HasPrefix(call, "stop ") && strings.HasSuffix(call, " "+unitGateway) {
			stops++
			data, _ := os.ReadFile(h.env.P(filepath.Join(targets[0].folder(), hardeningFile)))
			stoppedUnfenced = stoppedUnfenced || !strings.Contains(string(data), lifecycleFenceTag)
		}
	}
	requireOK(t, h.run(Options{Action: ActionUpgrade, PayloadDir: h.payload("1.0.3"), ProductVersion: "1.0.3"}))
	if stops == 0 || stoppedUnfenced {
		t.Fatalf("the gateway stopped %d times, with an unfenced old hook: %t", stops, stoppedUnfenced)
	}
}

// replacedHardening103 is the decision of a 1.0.3 _hardening.sh that a
// managed shell hook's fail_unreachable reads, verbatim, with the two
// failure loggers its fail_response and the 1.0.2 Copilot CLI hook call
// (their logging left out). TestR104 compat runs against the released
// files are in the report (GAP-1123).
const replacedHardening103 = `#!/bin/bash
# defenseclaw-managed-hook v9
defenseclaw_should_fail_closed_on_unreachable() {
  case "${FAIL_MODE:-open}" in
    closed) return 0 ;;
  esac
  case "${DEFENSECLAW_STRICT_AVAILABILITY:-0}" in
    1|true|TRUE|yes|YES) return 0 ;;
    *) return 1 ;;
  esac
}
defenseclaw_log_hook_failure() {
  printf 'logged %s\n' "$5" >&2
}
defenseclaw_log_hook_delivery_failure() {
  printf 'logged %s\n' "$5" >&2
}`

// replacedHooks are the released managed shell hooks' failure paths: each
// sources _hardening.sh when it starts and bakes the administrator's open.
// A 1.0.3 hook exits 2 (block) on an unreachable gateway only when the
// outage answers closed, and on a reply that is no answer only when
// FAIL_MODE is closed; the 1.0.2 Copilot CLI hook allowed every unreachable
// call.
var replacedHooks = map[string]string{
	"claude-code-hook.sh": `#!/bin/bash
HOOK_DIR="$(cd -P -- "${0%/*}" && pwd)"
. "${HOOK_DIR}/_hardening.sh"
FAIL_MODE="open"
fail_unreachable() {
  if defenseclaw_should_fail_closed_on_unreachable; then
    exit 2
  fi
  exit 0
}
fail_unreachable "gateway unreachable"
`,
	"claude-code-reply-hook.sh": `#!/bin/bash
HOOK_DIR="$(cd -P -- "${0%/*}" && pwd)"
. "${HOOK_DIR}/_hardening.sh"
FAIL_MODE="open"
fail_response() {
  defenseclaw_log_hook_delivery_failure claudecode claude-code-hook "$1" response "$FAIL_MODE"
  if [ "$FAIL_MODE" = "open" ]; then
    exit 0
  fi
  exit 2
}
fail_response "gateway returned HTTP 418"
`,
	"copilot-hook.sh": `#!/bin/bash
HOOK_DIR="$(cd -P -- "${0%/*}" && pwd)"
. "${HOOK_DIR}/_hardening.sh"
FAIL_MODE="open"
COPILOT_HOOK_EVENT="${2:-preToolUse}"
fail_unreachable() {
  defenseclaw_log_hook_failure copilot copilot-hook "$1" transport "$FAIL_MODE"
  exit 0
}

fail_unreachable "gateway unreachable"
`,
}

// The 1.0.2 Copilot hook puts its registered event in COPILOT_HOOK_EVENT.
// permissionRequest needs a different native deny body from preToolUse.
func TestFencedReplacedCopilotAnswersBothNativeEvents(t *testing.T) {
	if _, err := os.Stat("/bin/bash"); err != nil {
		t.Skip("no /bin/bash")
	}
	home := t.TempDir()
	folder := filepath.Join(home, ".defenseclaw", "hooks")
	writeReplacedHooks(t, folder, replacedHardening103)
	marker := filepath.Join(t.TempDir(), "lifecycle.active")
	if err := os.WriteFile(marker, []byte("1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if replaced, err := fenceHardening(home, filepath.Join(".defenseclaw", "hooks"), os.Getuid(), lifecycleFence(marker)); err != nil || !replaced {
		t.Fatalf("fence = %v, %v", replaced, err)
	}
	for _, tc := range []struct{ event, want, other string }{
		{"preToolUse", `"permissionDecision":"deny"`, `"behavior":"deny"`},
		{"permissionRequest", `"behavior":"deny"`, `"permissionDecision":"deny"`},
	} {
		t.Run(tc.event, func(t *testing.T) {
			cmd := exec.Command("/bin/bash", filepath.Join(folder, "copilot-hook.sh"), "--event", tc.event)
			cmd.Env = []string{"PATH=/usr/bin:/bin"}
			out, err := cmd.Output()
			if err != nil || !strings.Contains(string(out), tc.want) || strings.Contains(string(out), tc.other) {
				t.Fatalf("event %s: output %q, error %v; want %s only", tc.event, out, err, tc.want)
			}
		})
	}
}

func writeReplacedHooks(t *testing.T, folder, hardening string) {
	t.Helper()
	if err := os.MkdirAll(folder, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(folder, hardeningFile), []byte(hardening), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, script := range replacedHooks {
		if err := os.WriteFile(filepath.Join(folder, name), []byte(script), 0o700); err != nil {
			t.Fatal(err)
		}
	}
}

// runReplacedHooks runs every replaced hook and returns whether each
// blocked its call: exit 2, or Copilot's deny on its output.
func runReplacedHooks(t *testing.T, folder string) map[string]bool {
	t.Helper()
	blocks := map[string]bool{}
	for name := range replacedHooks {
		cmd := exec.Command("/bin/bash", filepath.Join(folder, name))
		cmd.Env = []string{"PATH=/usr/bin:/bin"}
		out, err := cmd.Output()
		var exit *exec.ExitError
		switch {
		case err == nil:
			blocks[name] = strings.Contains(string(out), `"permissionDecision":"deny"`)
		case errors.As(err, &exit) && exit.ExitCode() == 2:
			blocks[name] = true
		default:
			t.Fatalf("%s: %v", name, err)
		}
	}
	return blocks
}

func requireBlocks(t *testing.T, step string, got map[string]bool, want bool) {
	t.Helper()
	for name := range replacedHooks {
		if got[name] != want {
			t.Fatalf("%s: %s blocks=%v, want %v", step, name, got[name], want)
		}
	}
}

// GAP-1123: a 1.0.3 managed shell hook under the administrator's open let
// a call run while the 1.0.4 lifecycle had the gateway stopped: it cannot
// read the lifecycle run marker, and the guardian renders this release's
// hooks only after the new gateway is ready. The fence the run puts in the
// replaced _hardening.sh makes such a hook answer closed while the marker
// exists, and as before once it is gone; a file that reads the marker
// itself, one fenced already, and folders and files the account does not
// own or that are symlinks are left alone.
func TestFencedReplacedShellHookAnswersClosedWhileTheLifecycleRuns(t *testing.T) {
	if _, err := os.Stat("/bin/bash"); err != nil {
		t.Skip("no /bin/bash")
	}
	uid := os.Getuid()
	marker := filepath.Join(t.TempDir(), "defenseclaw-lifecycle.active")
	fence := lifecycleFence(marker)
	home := t.TempDir()
	folder := filepath.Join(home, ".defenseclaw", "hooks")
	writeReplacedHooks(t, folder, replacedHardening103)
	rel := filepath.Join(".defenseclaw", "hooks")
	if err := os.WriteFile(marker, []byte("1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	requireBlocks(t, "control: the unfenced hooks during the lifecycle (their open allows)", runReplacedHooks(t, folder), false)
	before, err := os.Stat(filepath.Join(folder, hardeningFile))
	if err != nil {
		t.Fatal(err)
	}
	replaced, err := fenceHardening(home, rel, uid, fence)
	if err != nil || !replaced {
		t.Fatalf("fence = %v, %v; want the replaced file fenced", replaced, err)
	}
	requireBlocks(t, "fenced, while the lifecycle runs", runReplacedHooks(t, folder), true)
	// A symlink marker counts too (the hooks accept any file type).
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(home, "nowhere"), marker); err != nil {
		t.Fatal(err)
	}
	requireBlocks(t, "fenced, dangling marker", runReplacedHooks(t, folder), true)
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	requireBlocks(t, "fenced, after the lifecycle (the administrator's open)", runReplacedHooks(t, folder), false)
	after, err := os.Stat(filepath.Join(folder, hardeningFile))
	if err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(filepath.Join(folder, hardeningFile))
	if !strings.HasPrefix(string(data), replacedHardening103) || !strings.HasSuffix(string(data), fence) {
		t.Fatal("the fenced file does not keep the replaced bytes followed by the fence")
	}
	if os.SameFile(before, after) {
		t.Fatal("the fence was written in place, not renamed over the file")
	}
	if after.Mode().Perm() != 0o600 || after.Sys().(*syscall.Stat_t).Uid != uint32(uid) {
		t.Fatalf("the fenced file is %v uid %d, want 0600 and the account's", after.Mode().Perm(), after.Sys().(*syscall.Stat_t).Uid)
	}
	entries, _ := os.ReadDir(folder)
	if len(entries) != len(replacedHooks)+1 {
		t.Fatalf("the fence left a temporary file: %v", entries)
	}

	// Fenced once: a second run neither appends again nor fails.
	if replaced, err := fenceHardening(home, rel, uid, fence); err != nil || !replaced {
		t.Fatalf("second fence = %v, %v", replaced, err)
	}
	if again, _ := os.ReadFile(filepath.Join(folder, hardeningFile)); string(again) != string(data) {
		t.Fatal("a second run fenced the file again")
	}

	// This release's file reads the marker itself: left alone.
	current := t.TempDir()
	writeReplacedHooks(t, filepath.Join(current, rel), "#!/bin/bash\n"+lifecycleMarkerReader+" {\n  return 1\n}\n")
	if replaced, err := fenceHardening(current, rel, uid, fence); err != nil || replaced {
		t.Fatalf("this release's _hardening.sh: fence = %v, %v; want it left alone", replaced, err)
	}

	// No hook folder, or no file: nothing to fence.
	if replaced, err := fenceHardening(t.TempDir(), rel, uid, fence); err != nil || replaced {
		t.Fatalf("no hook folder: fence = %v, %v", replaced, err)
	}

	// A symlink is never followed, as the folder or the file.
	linked := t.TempDir()
	if err := os.MkdirAll(filepath.Join(linked, ".defenseclaw"), 0o700); err != nil {
		t.Fatal(err)
	}
	elsewhere := t.TempDir()
	writeReplacedHooks(t, elsewhere, replacedHardening103)
	if err := os.Symlink(elsewhere, filepath.Join(linked, rel)); err != nil {
		t.Fatal(err)
	}
	if _, err := fenceHardening(linked, rel, uid, fence); err == nil {
		t.Fatal("a symlinked hook folder was followed")
	}
	fileLink := t.TempDir()
	if err := os.MkdirAll(filepath.Join(fileLink, rel), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(elsewhere, hardeningFile), filepath.Join(fileLink, rel, hardeningFile)); err != nil {
		t.Fatal(err)
	}
	if _, err := fenceHardening(fileLink, rel, uid, fence); err == nil {
		t.Fatal("a symlinked _hardening.sh was followed")
	}
	if data, _ := os.ReadFile(filepath.Join(elsewhere, hardeningFile)); string(data) != replacedHardening103 {
		t.Fatal("a symlink target was changed")
	}
	// A folder of another account is refused.
	if _, err := fenceHardening(home, rel, uid+1, fence); err == nil {
		t.Fatal("a folder the account does not own was fenced")
	}
}

// GAP-1123: the lifecycle fences every enrolled account's replaced hooks
// before it stops the gateway (an upgrade, a repair, a change that
// restarts it), and waits for the replaced hooks' calls already running
// while the gateway still answers them; a call still running at the end of
// the wait is reported. A process that started after the fence, or of
// another account, or that runs no hook of the folder, is not waited for.
// GAP-1710: a managed 1.0.2 -> 1.0.4 upgrade left the 1.0.2 generic shell
// hook set (its _hardening.sh and inspect-*.sh) in the managed data
// directory, neither refreshed nor removed. The upgrade removes a replaced
// release's set and keeps the folder's sidecars and tokens; a current set
// (its _hardening.sh reads the lifecycle marker) stays.
func TestUpgradeRetiresTheReplacedMachineShellHookSet(t *testing.T) {
	for name, current := range map[string]bool{"replaced 1.0.2 set": false, "current set": true} {
		t.Run(name, func(t *testing.T) {
			h := newTestHost(t, "linux")
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.2")}))
			dir := filepath.Join(h.env.Layout.DataDir, "hooks")
			hardening := replacedHardening103
			if current {
				hardening += "\n" + lifecycleMarkerReader + " { return 1; }\n"
			}
			for _, file := range replacedMachineShellHooks {
				body := "#!/bin/sh\nexit 0\n"
				if file == hardeningFile {
					body = hardening
				}
				writeHostFile(t, h, filepath.Join(dir, file), body)
			}
			keep := []string{".hookcfg", ".hookcfg.openclaw", ".hook-openclaw.token"}
			for _, file := range keep {
				writeHostFile(t, h, filepath.Join(dir, file), "kept\n")
			}
			requireOK(t, h.run(Options{Action: ActionUpgrade, PayloadDir: h.payload("1.0.4"), ProductVersion: "1.0.4"}))
			for _, file := range replacedMachineShellHooks {
				_, err := os.Lstat(h.env.P(filepath.Join(dir, file)))
				if current && err != nil {
					t.Fatalf("the current %s was removed: %v", file, err)
				}
				if !current && !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("the replaced %s was kept (err %v)", file, err)
				}
			}
			for _, file := range keep {
				if _, err := os.Lstat(h.env.P(filepath.Join(dir, file))); err != nil {
					t.Fatalf("%s was removed: %v", file, err)
				}
			}
		})
	}
}

func TestLifecycleFencesReplacedShellHooksBeforeItStopsTheGateway(t *testing.T) {
	if _, err := os.Stat("/bin/bash"); err != nil {
		t.Skip("no /bin/bash")
	}
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
			uid := os.Getuid()
			home := "/home/alice"
			if goos == "darwin" {
				home = "/Users/alice"
			}
			writeHostFile(t, h, h.env.Layout.ManifestPath, fmt.Sprintf("version: 1\ntargets:\n  - user: alice\n    uid: %d\n    user_home: %s\n    connector: claudecode\n  - user: alice\n    uid: %d\n    user_home: %s\n    connector: codex\n", uid, home, uid, home))
			folder := filepath.Join(home, ".defenseclaw", "hooks")
			if err := os.MkdirAll(h.env.P(home), 0o700); err != nil {
				t.Fatal(err)
			}
			writeReplacedHooks(t, h.env.P(folder), replacedHardening103)
			now := time.Now()
			h.env.ReplacedHookCallsTimeout = 300 * time.Millisecond
			hook := filepath.Join(folder, "claude-code-hook.sh")
			if goos == "linux" {
				boot := now.Add(-time.Hour)
				writeHostFile(t, h, "/proc/stat", fmt.Sprintf("cpu 0 0 0 0\nbtime %d\n", boot.Unix()))
				process := func(pid, cmdline string, started time.Time) {
					writeHostFile(t, h, "/proc/"+pid+"/cmdline", cmdline)
					ticks := int64(started.Sub(boot) / (10 * time.Millisecond))
					writeHostFile(t, h, "/proc/"+pid+"/stat", fmt.Sprintf("%s (bash) S 1 %s %s%d 0 0", pid, pid, strings.Repeat("0 ", 16), ticks))
				}
				process("7001", "/bin/bash\x00"+hook+"\x00", now.Add(-5*time.Second))
				process("7002", "/bin/bash\x00"+hook+"\x00", now.Add(10*time.Second)) // after the fence
				process("7003", "/bin/bash\x00/home/bob/other.sh\x00", now.Add(-5*time.Second))
			} else {
				setDarwinProcessArgv(t, func(int) ([]string, error) { return nil, errors.New("argv unavailable") })
				h.runner.ps = strings.Join([]string{
					fmt.Sprintf("7001 %d 00:05 /bin/bash %s", uid, hook),
					fmt.Sprintf("7003 %d 00:05 /bin/bash /Users/bob/other.sh", uid),
					fmt.Sprintf("7004 %d 00:05 /bin/bash %s", uid+1, hook),
				}, "\n")
			}
			gateway := unitGateway
			if goos == "darwin" {
				gateway = labelGateway
			}
			var stops int
			var unfenced []string
			h.services.observe = func(call string) {
				if !strings.HasPrefix(call, "stop ") || !strings.HasSuffix(call, " "+gateway) {
					return
				}
				stops++
				data, _ := os.ReadFile(h.env.P(filepath.Join(folder, hardeningFile)))
				if !strings.Contains(string(data), lifecycleFenceTag) {
					unfenced = append(unfenced, call)
				}
			}
			r := h.run(Options{Action: ActionUpgrade, PayloadDir: h.payload("1.0.1"), ProductVersion: "1.0.1"})
			requireOK(t, r)
			if stops == 0 || len(unfenced) > 0 {
				t.Fatalf("gateway stops %d, before the fence: %v", stops, unfenced)
			}
			got := messagesOf(r.Warnings, codeReplacedHookCalls)
			if !strings.Contains(got, "alice (pid 7001)") || strings.Contains(got, "7002") || strings.Contains(got, "7003") || strings.Contains(got, "7004") {
				t.Fatalf("the replaced hook calls reported are %q, want exactly pid 7001", got)
			}
			if hasWarning(r, codeReplacedHooks) {
				t.Fatalf("unexpected fence warning: %q", messagesOf(r.Warnings, codeReplacedHooks))
			}
			// Without the call running, nothing is reported; the folder is
			// fenced already.
			if goos == "linux" {
				if err := os.RemoveAll(h.env.P("/proc/7001")); err != nil {
					t.Fatal(err)
				}
			} else {
				h.runner.ps = ""
			}
			r = h.run(Options{Action: ActionRepair})
			requireOK(t, r)
			if hasWarning(r, codeReplacedHookCalls) || hasWarning(r, codeReplacedHooks) {
				t.Fatalf("a repair with no replaced hook call running warned: %+v", r.Warnings)
			}
		})
	}
}

func TestReplacedHookDrainIncludesCallsStartedWhileOtherHomesWereFenced(t *testing.T) {
	h := newTestHost(t, "linux")
	boot := time.Now().Add(-time.Hour).Truncate(time.Second)
	writeHostFile(t, h, "/proc/stat", fmt.Sprintf("cpu 0 0 0 0\nbtime %d\n", boot.Unix()))
	uid := os.Getuid()
	first := "/home/alice/.defenseclaw/hooks"
	second := "/home/bob/.defenseclaw/hooks"
	start := boot.Add(time.Minute)
	for _, item := range []struct {
		pid     string
		hook    string
		started time.Time
	}{
		{"7001", first + "/claude-code-hook.sh", start.Add(-time.Second)},
		{"7002", second + "/claude-code-hook.sh", start.Add(2 * time.Second)},
		{"7003", first + "/claude-code-hook.sh", start.Add(2 * time.Second)},
	} {
		writeHostFile(t, h, "/proc/"+item.pid+"/cmdline", "/bin/bash\x00"+item.hook+"\x00")
		ticks := int64(item.started.Sub(boot) / (10 * time.Millisecond))
		writeHostFile(t, h, "/proc/"+item.pid+"/stat", fmt.Sprintf("%s (bash) S 1 %s %s%d 0 0", item.pid, item.pid, strings.Repeat("0 ", 16), ticks))
	}
	folders := []replacedHookFolder{
		{user: "alice", uid: uid, path: first, fencedAt: start},
		{user: "bob", uid: uid, path: second, fencedAt: start.Add(3 * time.Second)},
	}
	got := h.env.replacedHookCalls(context.Background(), folders)
	if want := []string{"alice (pid 7001)", "bob (pid 7002)"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("drain calls = %v, want %v (the later home was not fenced at the first cutoff)", got, want)
	}
}
