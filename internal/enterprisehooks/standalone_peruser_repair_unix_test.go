//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// standaloneOpenHandsHome returns a home an OpenHands standalone install
// works in on this OS (macOS also needs the user's own OpenHands image).
func standaloneOpenHandsHome(t *testing.T) string {
	t.Helper()
	home := newTestHome(t)
	if runtime.GOOS == "darwin" {
		withoutMachineAgentPrefixes(t)
		writeUVToolOpenHands(t, home)
	}
	return home
}

func openHandsStandaloneOptions(home, mode string) InstallOptions {
	failMode := "open"
	if mode == "action" {
		failMode = "closed"
	}
	return InstallOptions{
		ConnectorName: "openhands",
		UserHome:      home,
		OwnerUID:      os.Getuid(),
		OwnerGID:      os.Getgid(),
		APIAddr:       "127.0.0.1:18970",
		ProxyAddr:     "127.0.0.1:4000",
		APIToken:      strings.Repeat("a", 64),
		OTLPPathToken: strings.Repeat("d", 64),
		GuardrailMode: mode,
		HookFailMode:  failMode,
		AgentVersion:  "1.16.0",
		Registry:      connector.NewDefaultRegistry(),
	}
}

func requirePerm(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("%s mode = %o, want %o", path, got, want)
	}
}

// A standard user who made their own ~/.defenseclaw (or its hooks
// directory) unreadable stopped every repair of their hooks: the worker,
// which runs as that user, failed with "permission denied" on each cycle
// until the user undid the mode. The repair now restores the owner-only
// mode first. A link in place of the data directory is still refused and
// its target left alone, and the Secure Client profile is unchanged.
func TestStandaloneRepairRestoresTheUsersOwnDataDirModes(t *testing.T) {
	requireEnterpriseHookInstaller(t)
	skipIfRoot(t)
	setStandaloneProfileForTest(t, true)
	home := standaloneOpenHandsHome(t)
	opts := openHandsStandaloneOptions(home, "action")
	if _, err := Install(context.Background(), opts); err != nil {
		t.Fatalf("first install: %v", err)
	}
	dataDir := filepath.Join(home, ".defenseclaw")
	hooks := filepath.Join(dataDir, "hooks")
	t.Cleanup(func() {
		_ = os.Chmod(dataDir, 0o700)
		_ = os.Chmod(hooks, 0o700)
	})
	repair := opts
	repair.AllowMissingHookConfigRepair = true
	for _, broken := range []string{hooks, dataDir} {
		if err := os.Chmod(broken, 0); err != nil {
			t.Fatal(err)
		}
		if _, err := Verify(context.Background(), opts); err == nil {
			t.Fatalf("verify passed with %s unreadable", broken)
		}
		if _, err := Install(context.Background(), repair); err != nil {
			t.Fatalf("repair with %s unreadable: %v", broken, err)
		}
		requirePerm(t, dataDir, 0o700)
		requirePerm(t, hooks, 0o700)
		if _, err := Verify(context.Background(), opts); err != nil {
			t.Fatalf("verify after the repair of %s: %v", broken, err)
		}
	}

	// A group- and world-writable data directory is tightened too.
	if err := os.Chmod(dataDir, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := Install(context.Background(), repair); err != nil {
		t.Fatalf("repair with a loosened data dir: %v", err)
	}
	requirePerm(t, dataDir, 0o700)

	// Outside the standalone profile the mode is not touched.
	setStandaloneProfileForTest(t, false)
	if err := os.Chmod(dataDir, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := Install(context.Background(), repair); err == nil {
		t.Fatal("Secure Client install passed with an unreadable data dir")
	}
	requirePerm(t, dataDir, 0)
	if err := os.Chmod(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	setStandaloneProfileForTest(t, true)

	// A link in place of the data directory is refused, and its target's
	// mode is left as it is.
	elsewhere := filepath.Join(home, "elsewhere")
	if err := os.Mkdir(elsewhere, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(dataDir, dataDir+".moved"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, dataDir); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(elsewhere, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(elsewhere, 0o700) })
	if _, err := Install(context.Background(), repair); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("repair through a linked data dir = %v, want the symlink refusal", err)
	}
	requirePerm(t, elsewhere, 0o500)
}

// hermesStandaloneOptions installs Hermes for home, whose ~/.hermes config
// the connector resolves from HOME.
func hermesStandaloneOptions(t *testing.T, home string) InstallOptions {
	t.Helper()
	t.Setenv("HOME", home)
	config := filepath.Join(home, ".hermes", "config.yaml")
	mustMkdir(t, filepath.Dir(config), 0o700)
	if err := os.WriteFile(config, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	opts := openHandsStandaloneOptions(home, "observe")
	opts.ConnectorName = "hermes"
	opts.AgentVersion = "0.9.0"
	return opts
}

// Unix verification read only the agent config reference and the lock, so
// a user who deleted ~/.defenseclaw/hooks/hermes-hook.sh (or edited it, or
// removed the shared _hardening.sh) left the Hermes config pointing at a
// missing or changed script while every check stayed green and no repair
// ran. The standalone verification now compares the hook runtime files
// with the digests the install recorded, so the guardian's verify-or-repair
// pass re-renders them.
func TestStandaloneVerifyReportsAndRepairsAChangedHookScript(t *testing.T) {
	requireEnterpriseHookInstaller(t)
	skipIfRoot(t)
	setStandaloneProfileForTest(t, true)
	home := newTestHome(t)
	opts := hermesStandaloneOptions(t, home)
	if _, err := Install(context.Background(), opts); err != nil {
		t.Fatalf("install: %v", err)
	}
	if _, err := Verify(context.Background(), opts); err != nil {
		t.Fatalf("verify after the install: %v", err)
	}
	hooks := filepath.Join(home, ".defenseclaw", "hooks")
	script := filepath.Join(hooks, "hermes-hook.sh")
	original, err := os.ReadFile(script)
	if err != nil {
		t.Fatal(err)
	}
	repair := opts
	repair.AllowMissingHookConfigRepair = true
	for _, change := range []struct {
		name, path, want string
		apply            func(path string) error
	}{
		{"deleted hermes-hook.sh", script, "missing", os.Remove},
		{"edited hermes-hook.sh", script, "changed since it was installed", func(path string) error {
			return os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o700)
		}},
		{"deleted _hardening.sh", filepath.Join(hooks, "_hardening.sh"), "missing", os.Remove},
		{"deleted inspect-tool.sh", filepath.Join(hooks, "inspect-tool.sh"), "missing", os.Remove},
	} {
		if err := change.apply(change.path); err != nil {
			t.Fatal(err)
		}
		if _, err := Verify(context.Background(), opts); err == nil || !strings.Contains(err.Error(), change.want) ||
			!strings.Contains(err.Error(), change.path) {
			t.Fatalf("%s: verify = %v, want %q for %s", change.name, err, change.want, change.path)
		}
		if _, err := Install(context.Background(), repair); err != nil {
			t.Fatalf("%s: repair: %v", change.name, err)
		}
		if _, err := Verify(context.Background(), opts); err != nil {
			t.Fatalf("%s: verify after the repair: %v", change.name, err)
		}
	}
	if repaired, err := os.ReadFile(script); err != nil || string(repaired) != string(original) {
		t.Fatalf("hermes-hook.sh after the repairs differs from the install (err=%v)", err)
	}

	// The Secure Client profile keeps its earlier verification.
	setStandaloneProfileForTest(t, false)
	if err := os.Remove(script); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(context.Background(), opts); err != nil {
		t.Fatalf("Secure Client verify changed: %v", err)
	}
}

// The per-user OpenHands runtime kept the fail-open hook and runtime
// records of an observe-mode install after the administrator switched
// guardrail.mode to action: verification never compared the rendered
// fail mode with the configuration, so nothing re-rendered it. It now does,
// for the lock and for the .hookcfg records the scripts read.
func TestStandaloneVerifyFollowsAnObserveToActionChangeForOpenHands(t *testing.T) {
	requireEnterpriseHookInstaller(t)
	skipIfRoot(t)
	setStandaloneProfileForTest(t, true)
	home := standaloneOpenHandsHome(t)
	observe := openHandsStandaloneOptions(home, "observe")
	if _, err := Install(context.Background(), observe); err != nil {
		t.Fatalf("observe install: %v", err)
	}
	if _, err := Verify(context.Background(), observe); err != nil {
		t.Fatalf("observe verify: %v", err)
	}
	flat := filepath.Join(home, ".defenseclaw", "hooks", ".hookcfg.openhands")
	requireFailMode := func(want string) {
		t.Helper()
		data, err := os.ReadFile(flat)
		if err != nil || !strings.Contains(string(data), "DEFENSECLAW_FAIL_MODE="+want+"\n") {
			t.Fatalf(".hookcfg.openhands = %q (err=%v), want fail mode %s", data, err, want)
		}
	}
	requireFailMode("open")

	action := openHandsStandaloneOptions(home, "action")
	if _, err := Verify(context.Background(), action); err == nil || !strings.Contains(err.Error(), `rendered for fail mode "open"`) {
		t.Fatalf("verify after the switch to action = %v, want the fail-mode mismatch", err)
	}
	repair := action
	repair.AllowMissingHookConfigRepair = true
	if _, err := Install(context.Background(), repair); err != nil {
		t.Fatalf("repair after the switch: %v", err)
	}
	requireFailMode("closed")
	if _, err := Verify(context.Background(), action); err != nil {
		t.Fatalf("verify after the repair: %v", err)
	}

	// An edited runtime record is reported too.
	if err := os.WriteFile(flat, []byte("DEFENSECLAW_CONNECTOR=openhands\nDEFENSECLAW_FAIL_MODE=open\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(context.Background(), action); err == nil || !strings.Contains(err.Error(), ".hookcfg.openhands") {
		t.Fatalf("verify with an edited runtime record = %v, want it reported", err)
	}
	if _, err := Install(context.Background(), repair); err != nil {
		t.Fatalf("repair of the runtime record: %v", err)
	}
	requireFailMode("closed")
	if _, err := Verify(context.Background(), action); err != nil {
		t.Fatalf("verify after repairing the runtime record: %v", err)
	}
}

// One home with every per-user connector installed follows a guardrail
// mode switch both ways: after the reinstall for the new mode, Verify
// passes for every connector, so the guardian's next cycle repairs nothing
// (a Cursor row in action mode used to be repaired on every cycle), and
// verification reports no drift right after an install.
func TestStandaloneVerifyFollowsModeSwitchesInOneHome(t *testing.T) {
	requireEnterpriseHookInstaller(t)
	skipIfRoot(t)
	setStandaloneProfileForTest(t, true)
	home := standaloneOpenHandsHome(t)
	t.Setenv("HOME", home)
	// Devin reads XDG_CONFIG_HOME, which CI runners set outside this home.
	t.Setenv("XDG_CONFIG_HOME", "")
	for _, config := range []string{".hermes/config.yaml", ".config/devin/config.json"} {
		path := filepath.Join(home, config)
		mustMkdir(t, filepath.Dir(path), 0o700)
		if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	connectors := []struct{ name, version string }{
		{"hermes", "0.19.0"}, {"openhands", "1.16.0"}, {"kiro", "2.24.1"}, {"copilot", "1.0.20"},
		{"devin", "3000.4.25"}, {"amp", "0.0.1785334300"}, {"opencode", "1.18.31"},
		{"antigravity", "1.2.11"}, {"cursor", "2.4.1"}, {"codex", "0.145.0"}, {"claudecode", "2.1.220"},
	}
	for _, mode := range []string{"observe", "action", "observe"} {
		for _, c := range connectors {
			opts := openHandsStandaloneOptions(home, mode)
			opts.ConnectorName, opts.AgentVersion = c.name, c.version
			if _, err := Install(context.Background(), opts); err != nil {
				t.Fatalf("%s %s: install: %v", c.name, mode, err)
			}
		}
		for _, c := range connectors {
			opts := openHandsStandaloneOptions(home, mode)
			opts.ConnectorName, opts.AgentVersion = c.name, c.version
			if _, err := Verify(context.Background(), opts); err != nil {
				t.Fatalf("%s after switching to %s: verify: %v", c.name, mode, err)
			}
		}
	}

	// An agent on an older hook contract installs in observe mode only, and
	// verifies right after its install too.
	for _, c := range []struct{ name, version, config string }{
		{"hermes", "0.9.0", ".hermes/config.yaml"}, {"copilot", "1.0.3", ""},
		{"devin", "2026.1.2", ".config/devin/config.json"}, {"amp", "0.0.170", ""}, {"opencode", "1.2.0", ""},
	} {
		home := standaloneOpenHandsHome(t)
		t.Setenv("HOME", home)
		if c.config != "" {
			path := filepath.Join(home, c.config)
			mustMkdir(t, filepath.Dir(path), 0o700)
			if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		opts := openHandsStandaloneOptions(home, "observe")
		opts.ConnectorName, opts.AgentVersion = c.name, c.version
		if _, err := Install(context.Background(), opts); err != nil {
			t.Fatalf("%s %s: install: %v", c.name, c.version, err)
		}
		if _, err := Verify(context.Background(), opts); err != nil {
			t.Fatalf("%s %s: verify right after the install: %v", c.name, c.version, err)
		}
	}
}
