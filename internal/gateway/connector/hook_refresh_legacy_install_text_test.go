package connector

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestRefreshNamesTheInstallInA102HardeningScript: from a published 1.0.2
// start, the installer's fail-mode refresh leaves 1.0.2's _hardening.sh in
// place while it stops the gateway, and that file says "this account's
// gateway is not running; run `defenseclaw-gateway start`" during the
// install window (GAP-1899). After the refresh the same 1.0.2 helper names
// the install while the lock is held and answers as before without it.
func TestRefreshNamesTheInstallInA102HardeningScript(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell hooks")
	}
	released, err := os.ReadFile(filepath.Join("testdata", "released-hooks", "1.0.2", "_hardening.sh"))
	if err != nil {
		t.Fatal(err)
	}
	current, err := hookFS.ReadFile("hooks/_hardening.sh")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(current), legacyInstallWindowText) {
		t.Fatal("legacyInstallWindowText is not the sentence this release's _hardening.sh prints")
	}
	data := filepath.Join(t.TempDir(), "data")
	hookDir := filepath.Join(data, "hooks")
	if err := os.MkdirAll(hookDir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(hookDir, "_hardening.sh")
	if err := os.WriteFile(path, released, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(hookDir, ".hookcfg.claudecode"), hookRuntimeFlatRecord("claudecode", "open", ""), 0o600); err != nil {
		t.Fatal(err)
	}
	nextStep := func(t *testing.T) string {
		t.Helper()
		// A 1.0.2 hook sources the helper from its folder and asks it for
		// the next step of a refused connection (fail_unreachable).
		cmd := exec.Command("bash", "-c", `set -euo pipefail; . "$1/_hardening.sh"; defenseclaw_unreachable_next_step || true`, "hook", hookDir)
		cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + filepath.Join(t.TempDir(), "home"), "DEFENSECLAW_HOME=" + data}
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("next step: %v\n%s", err, out)
		}
		return string(out)
	}
	if err := os.Mkdir(filepath.Join(data, ".install.lock"), 0o700); err != nil {
		t.Fatal(err)
	}
	if got := nextStep(t); strings.Contains(got, "being installed or upgraded") {
		t.Fatalf("fixture already names the install: %q", got)
	}

	refresh, err := RefreshHookFailModes(hookDir, func(string) string { return "closed" })
	if err != nil {
		t.Fatal(err)
	}
	if !containsString(refresh.Scripts, "_hardening.sh") {
		t.Fatalf("refresh scripts = %v, want _hardening.sh", refresh.Scripts)
	}
	if got := nextStep(t); got != legacyInstallWindowText {
		t.Fatalf("1.0.2 helper during the install window = %q, want the install sentence", got)
	}
	if err := os.Remove(filepath.Join(data, ".install.lock")); err != nil {
		t.Fatal(err)
	}
	if got := nextStep(t); strings.Contains(got, "being installed or upgraded") {
		t.Fatalf("1.0.2 helper without a lock = %q, want its own answer", got)
	}
	// A second refresh appends nothing; a file that already names the
	// install (1.0.3 on) is left as it is.
	before, _ := os.ReadFile(path)
	if _, err := RefreshHookFailModes(hookDir, func(string) string { return "closed" }); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(path)
	if string(after) != string(before) {
		t.Fatal("a second refresh changed _hardening.sh again")
	}
	for _, release := range []string{"1.0.3"} {
		body, err := os.ReadFile(filepath.Join("testdata", "released-hooks", release, "_hardening.sh"))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, body, 0o700); err != nil {
			t.Fatal(err)
		}
		if named, err := nameInstallInLegacyHardening(hookDir); err != nil || named {
			t.Fatalf("%s helper: named=%v err=%v, want untouched", release, named, err)
		}
	}
}
