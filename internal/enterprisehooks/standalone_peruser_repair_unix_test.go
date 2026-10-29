//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// standaloneOptions installs connectorName at agentVersion for home in
// guardrail mode (fail closed in action mode, open in observe mode).
func standaloneOptions(home, connectorName, mode, agentVersion string) InstallOptions {
	failMode := "open"
	if mode == "action" {
		failMode = "closed"
	}
	return InstallOptions{
		ConnectorName: connectorName,
		UserHome:      home,
		OwnerUID:      os.Getuid(),
		OwnerGID:      os.Getgid(),
		APIAddr:       "127.0.0.1:18970",
		ProxyAddr:     "127.0.0.1:4000",
		APIToken:      strings.Repeat("a", 64),
		OTLPPathToken: strings.Repeat("d", 64),
		GuardrailMode: mode,
		HookFailMode:  failMode,
		AgentVersion:  agentVersion,
		Registry:      connector.NewDefaultRegistry(),
	}
}

// writeAgentConfigs creates the empty agent configs the Hermes and Devin
// connectors require before an install under home.
func writeAgentConfigs(t *testing.T, home string, configs ...string) {
	t.Helper()
	for _, config := range configs {
		path := filepath.Join(home, config)
		mustMkdir(t, filepath.Dir(path), 0o700)
		if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
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
	// A version with a hook contract: the guardian installs none for a
	// version without one, in any mode (GAP-0151).
	return standaloneOptions(home, "hermes", "observe", "0.21.5")
}

// 'hermes profile delete' can leave profiles/.deleted behind. The managed
// verification of an intact default-profile registration still passes, and
// the guardian's ensure (Install again) succeeds without changing it; a real
// named profile still fails Verify.
func TestManagedHermesVerifyAndEnsureAcceptDeletedProfileMetadata(t *testing.T) {
	requireEnterpriseHookInstaller(t)
	skipIfRoot(t)
	setStandaloneProfileForTest(t, true)
	home := newTestHome(t)
	opts := hermesStandaloneOptions(t, home)
	opts.ManagedHookSocket = "/var/run/defenseclaw/hook.sock"
	opts.ManagedServiceUID = 461
	configPath := filepath.Join(home, ".hermes", "config.yaml")
	if _, err := Install(context.Background(), opts); err != nil {
		t.Fatalf("Install: %v", err)
	}
	mustMkdir(t, filepath.Join(home, ".hermes", "profiles", ".deleted", "coder"), 0o700)
	registered, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(context.Background(), opts); err != nil {
		t.Fatalf("Verify with profiles/.deleted: %v", err)
	}
	if _, err := Install(context.Background(), opts); err != nil {
		t.Fatalf("ensure (Install again) with profiles/.deleted: %v", err)
	}
	if after, err := os.ReadFile(configPath); err != nil || string(after) != string(registered) {
		t.Fatalf("ensure changed the Hermes registration (err %v)", err)
	}
	if _, err := Verify(context.Background(), opts); err != nil {
		t.Fatalf("Verify after ensure: %v", err)
	}
	mustMkdir(t, filepath.Join(home, ".hermes", "profiles", "coder"), 0o700)
	if _, err := Verify(context.Background(), opts); err == nil || !strings.Contains(err.Error(), "coder") {
		t.Fatalf("Verify with a named profile = %v, want it refused", err)
	}
}

// Unix verification read only the agent config reference and the lock, so
// a user who deleted ~/.defenseclaw/hooks/hermes-hook.sh (or edited it, or
// removed the shared _hardening.sh) left the Hermes config pointing at a
// missing or changed script while every check stayed green and no repair
// ran. The standalone verification now compares the hook runtime files
// with the digests the install recorded and with this release's render, so
// the guardian's verify-or-repair pass re-renders them, also after a package
// upgrade.
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
		// The runtime records and the scoped token the hook script reads
		// (GAP-0671, GAP-0424): moved aside, the guardian left them
		// missing while status and verify stayed green.
		{"moved .hookcfg.hermes", filepath.Join(hooks, ".hookcfg.hermes"), "missing", os.Remove},
		{"moved .hookcfg", filepath.Join(hooks, ".hookcfg"), "missing", os.Remove},
		{"moved .hook-hermes.token", filepath.Join(hooks, ".hook-hermes.token"), "missing", os.Remove},
		{"edited .hook-hermes.token", filepath.Join(hooks, ".hook-hermes.token"), "does not hold the credential", func(path string) error {
			return os.WriteFile(path, []byte(strings.Repeat("b", 64)+"\n"), 0o600)
		}},
		// After a package upgrade the script still matches the digest
		// recorded at its last write but carries the previous release's
		// render, so the digest alone kept verification green.
		{"previous release's hermes-hook.sh", script, "differs from the rendered template", func(path string) error {
			previous := append(append([]byte{}, original...), "# previous release\n"...)
			if err := os.WriteFile(path, previous, 0o700); err != nil {
				return err
			}
			lockPath := filepath.Join(home, ".defenseclaw", "hook_contract_lock.json")
			body, err := os.ReadFile(lockPath)
			if err != nil {
				return err
			}
			var lock map[string]any
			if err := json.Unmarshal(body, &lock); err != nil {
				return err
			}
			digests := lock["connectors"].(map[string]any)["hermes"].(map[string]any)["hook_script_digests"].(map[string]any)
			digests[filepath.Base(path)] = fmt.Sprintf("sha256:%x", sha256.Sum256(previous))
			if body, err = json.Marshal(lock); err != nil {
				return err
			}
			return os.WriteFile(lockPath, body, 0o600)
		}},
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

	// Secure Client keeps its existing registration-first verification: it
	// reports the missing owned command, without inspecting script digests.
	setStandaloneProfileForTest(t, false)
	if err := os.Remove(script); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(context.Background(), opts); err == nil || !strings.Contains(err.Error(), "owned hook command not present") {
		t.Fatalf("Secure Client verify = %v, want the existing missing registration error", err)
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
	home := newTestHome(t)
	opts := hermesStandaloneOptions(t, home)
	opts.GuardrailMode, opts.HookFailMode = "action", "closed"
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

// A managed in-agent plugin (Amp, OpenCode), its runtime lock and its
// custody receipt are all user-owned. An appended line with matching lock
// and receipt digests kept the old checks green, but verification must
// reject the edit and let the guardian reinstall the rendered file.
func TestStandaloneVerifyRepairsAnAppendedManagedPluginLine(t *testing.T) {
	requireEnterpriseHookInstaller(t)
	skipIfRoot(t)
	setStandaloneProfileForTest(t, true)
	previous := connector.AMPPluginPathOverride
	connector.AMPPluginPathOverride = ""
	t.Cleanup(func() { connector.AMPPluginPathOverride = previous })

	for _, tc := range []struct{ name, agentVersion string }{
		{"amp", "0.0.1785334225"},
		{"opencode", "opencode 2.1.4"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := newTestHome(t)
			t.Setenv("HOME", home)
			opts := standaloneOptions(home, tc.name, "action", tc.agentVersion)
			opts.ForeignHookGuardBinary = "/opt/defenseclaw/bin/defenseclaw-hook"
			ctx := context.Background()
			result, err := Install(ctx, opts)
			if err != nil {
				t.Fatalf("install: %v", err)
			}
			if len(result.HookConfigPaths) != 1 {
				t.Fatalf("plugin paths = %v", result.HookConfigPaths)
			}
			if _, err := Verify(ctx, opts); err != nil {
				t.Fatalf("verify installed plugin: %v", err)
			}
			plugin := result.HookConfigPaths[0]
			original, err := os.ReadFile(plugin)
			if err != nil {
				t.Fatal(err)
			}
			edited := append(append([]byte{}, original...), "// user line\n"...)
			if err := os.WriteFile(plugin, edited, 0o600); err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(edited)
			rewrite := func(path string, edit func(map[string]any)) {
				body, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				var doc map[string]any
				if err := json.Unmarshal(body, &doc); err != nil {
					t.Fatal(err)
				}
				edit(doc)
				if body, err = json.Marshal(doc); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, body, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			dataDir := filepath.Join(home, ".defenseclaw")
			rewrite(filepath.Join(dataDir, "hook_contract_lock.json"), func(lock map[string]any) {
				digests := lock["connectors"].(map[string]any)[tc.name].(map[string]any)["hook_script_digests"].(map[string]any)
				digests[filepath.Base(plugin)] = fmt.Sprintf("sha256:%x", sum)
			})
			rewrite(filepath.Join(dataDir, "connector_backups", tc.name, "config.json"), func(receipt map[string]any) {
				receipt["post_sha256"] = fmt.Sprintf("%x", sum)
			})
			if _, err := Verify(ctx, opts); err == nil || !strings.Contains(err.Error(), plugin) {
				t.Fatalf("verify edited plugin = %v, want drift naming %s", err, plugin)
			}
			repair := opts
			repair.AllowMissingHookConfigRepair = true
			if _, err := Install(ctx, repair); err != nil {
				t.Fatalf("repair: %v", err)
			}
			if _, err := Verify(ctx, opts); err != nil {
				t.Fatalf("verify repaired plugin: %v", err)
			}
			restored, err := os.ReadFile(plugin)
			if err != nil || string(restored) != string(original) {
				t.Fatalf("repair did not restore the rendered plugin (read error: %v)", err)
			}
		})
	}
}

// The per-user hook runtime kept the fail-open hook and runtime records of
// an observe-mode install after the administrator switched guardrail.mode
// to action: verification never compared the rendered fail mode with the
// configuration, so nothing re-rendered it. It now does, for the lock and
// for the .hookcfg records the scripts read.
func TestStandaloneVerifyFollowsAnObserveToActionChange(t *testing.T) {
	requireEnterpriseHookInstaller(t)
	skipIfRoot(t)
	setStandaloneProfileForTest(t, true)
	home := newTestHome(t)
	t.Setenv("HOME", home)
	observe := standaloneOptions(home, "kiro", "observe", "2.27.1")
	if _, err := Install(context.Background(), observe); err != nil {
		t.Fatalf("observe install: %v", err)
	}
	if _, err := Verify(context.Background(), observe); err != nil {
		t.Fatalf("observe verify: %v", err)
	}
	flat := filepath.Join(home, ".defenseclaw", "hooks", ".hookcfg.kiro")
	requireFailMode := func(want string) {
		t.Helper()
		data, err := os.ReadFile(flat)
		if err != nil || !strings.Contains(string(data), "DEFENSECLAW_FAIL_MODE="+want+"\n") {
			t.Fatalf(".hookcfg.kiro = %q (err=%v), want fail mode %s", data, err, want)
		}
	}
	requireFailMode("open")

	action := observe
	action.GuardrailMode, action.HookFailMode = "action", "closed"
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
	if err := os.WriteFile(flat, []byte("DEFENSECLAW_CONNECTOR=kiro\nDEFENSECLAW_FAIL_MODE=open\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(context.Background(), action); err == nil || !strings.Contains(err.Error(), ".hookcfg.kiro") {
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

// A named pipe in place of an agent's hooks file stalled the per-user
// worker until its deadline, and the admin saw only "worker for uid N timed
// out" for every connector of that user. Verify and repair now fail at once
// and name the file.
func TestStandaloneVerifyNamesAPipeInPlaceOfTheHooksFile(t *testing.T) {
	requireEnterpriseHookInstaller(t)
	skipIfRoot(t)
	setStandaloneProfileForTest(t, true)
	home := newTestHome(t)
	t.Setenv("HOME", home)
	opts := standaloneOptions(home, "cursor", "action", "2.4.1")
	if _, err := Install(context.Background(), opts); err != nil {
		t.Fatalf("install: %v", err)
	}
	path := filepath.Join(home, ".cursor", "hooks.json")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	errs := make(chan [2]error, 1)
	go func() {
		_, verifyErr := Verify(context.Background(), opts)
		_, installErr := Install(context.Background(), opts)
		errs <- [2]error{verifyErr, installErr}
	}()
	select {
	case got := <-errs:
		for i, err := range got {
			if err == nil || !strings.Contains(err.Error(), path+" is a named pipe") {
				t.Fatalf("step %d = %v, want an error naming the pipe %s", i, err, path)
			}
		}
	case <-time.After(10 * time.Second):
		t.Fatal("verify or repair blocked on the named pipe")
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
	home := newTestHome(t)
	t.Setenv("HOME", home)
	// Devin reads XDG_CONFIG_HOME, which CI runners set outside this home.
	t.Setenv("XDG_CONFIG_HOME", "")
	writeAgentConfigs(t, home, ".hermes/config.yaml", ".config/devin/config.json")
	connectors := []struct{ name, version string }{
		{"hermes", "0.21.5"}, {"kiro", "2.27.1"}, {"copilot", "1.0.20"},
		{"devin", "3000.4.25"}, {"amp", "0.0.1785334300"}, {"opencode", "2.1.4"},
		{"antigravity", "1.2.11"}, {"cursor", "2.4.1"}, {"codex", "0.145.0"}, {"claudecode", "2.1.220"},
	}
	for _, mode := range []string{"observe", "action", "observe"} {
		for _, c := range connectors {
			if _, err := Install(context.Background(), standaloneOptions(home, c.name, mode, c.version)); err != nil {
				t.Fatalf("%s %s: install: %v", c.name, mode, err)
			}
		}
		for _, c := range connectors {
			if _, err := Verify(context.Background(), standaloneOptions(home, c.name, mode, c.version)); err != nil {
				t.Fatalf("%s after switching to %s: verify: %v", c.name, mode, err)
			}
		}
	}

	// An agent version with no hook contract (below every contract's floor)
	// gets no hooks in observe mode either: they were rendered without a
	// contract and status reported the agent as covered (GAP-0151).
	for _, c := range []struct{ name, version, config string }{
		{"hermes", "0.9.0", ".hermes/config.yaml"}, {"copilot", "1.0.3", ""},
		{"devin", "2026.1.2", ".config/devin/config.json"}, {"amp", "0.0.170", ""}, {"opencode", "1.2.0", ""},
	} {
		home := newTestHome(t)
		t.Setenv("HOME", home)
		if c.config != "" {
			writeAgentConfigs(t, home, c.config)
		}
		opts := standaloneOptions(home, c.name, "observe", c.version)
		if _, err := Install(context.Background(), opts); err == nil ||
			!strings.Contains(err.Error(), "is not verified against a known hook contract") {
			t.Fatalf("%s %s: observe install = %v, want the hook_contract_unverified refusal", c.name, c.version, err)
		}
		if entries, _ := os.ReadDir(filepath.Join(home, ".defenseclaw", "hooks")); len(entries) != 0 {
			t.Fatalf("%s %s: hook runtime rendered: %v", c.name, c.version, entries)
		}
	}
}
