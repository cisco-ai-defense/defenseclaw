// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

const (
	outageNowDefaultConfig = "config_version: 9\nobservability: {}\nguardrail:\n  mode: observe\n"
	outageNowStrictConfig  = outageNowDefaultConfig + "  rule_pack: strict\n"
)

func writeOutageNowConfig(t *testing.T, dir, body string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if body == "" {
		return
	}
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// hookOutageFailModeNow answers from the config of the hook runtime at the
// time of the call, not from what the hooks recorded: a rule pack switched to
// strict after the gateway stopped closes the outage, and a config this
// release cannot load, a managed one or none closes it too.
func TestHookOutageFailModeNowReadsTheConfigOnDisk(t *testing.T) {
	for _, tc := range []struct {
		name, config, connector, want string
	}{
		{"default pack", outageNowDefaultConfig, "codex", "open"},
		{"action mode, default pack", "config_version: 9\nobservability: {}\nguardrail:\n  mode: action\n", "codex", "open"},
		{"permissive pack", outageNowDefaultConfig + "  rule_pack: permissive\n", "claudecode", "open"},
		{"strict pack", outageNowStrictConfig, "codex", "closed"},
		{"saved closed overrides default", outageNowDefaultConfig + "  hook_fail_mode: closed\n", "codex", "closed"},
		{"saved open overrides strict", outageNowStrictConfig + "  hook_fail_mode: open\n", "codex", "open"},
		{"connector closed overrides global open", outageNowDefaultConfig + "  hook_fail_mode: open\n  connectors:\n    codex:\n      hook_fail_mode: closed\n", "codex", "closed"},
		{"strict pack for this connector", outageNowDefaultConfig + "  connectors:\n    codex:\n      rule_pack: strict\n", "codex", "closed"},
		{"strict pack for another connector", outageNowDefaultConfig + "  connectors:\n    codex:\n      rule_pack: strict\n", "claudecode", "open"},
		{"upper-case connector name", outageNowStrictConfig, " CODEX ", "closed"},
		{"no connector", outageNowDefaultConfig, " ", "closed"},
		{"no config", "", "codex", "closed"},
		{"config this release cannot read", "config_version: 9\nguardrail: [\n", "codex", "closed"},
		{"an older config", "config_version: 7\nguardrail:\n  mode: observe\n", "codex", "closed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("DEFENSECLAW_HOME", home)
			t.Setenv("HOME", home)
			writeOutageNowConfig(t, home, tc.config)
			if got := hookOutageFailModeNow(tc.connector, filepath.Join(home, "hooks")); got != tc.want {
				t.Fatalf("hookOutageFailModeNow(%q) = %q, want %q", tc.connector, got, tc.want)
			}
		})
	}
}

// oss-outage-open review (loop round 3): the policy source of an outage is
// the config of the hook runtime asking (config.yaml in the data directory
// above its hooks folder). The hook process inherits the agent's
// environment, so a DEFENSECLAW_CONFIG or DEFENSECLAW_HOME that names another
// default-tier config must not reopen an outage the runtime's strict config
// closes; nor does it close one the runtime's default config opens. A config
// whose data_dir is another folder is not the runtime's config.
func TestHookOutageFailModeNowReadsOnlyTheRuntimesConfig(t *testing.T) {
	for _, tc := range []struct {
		name, runtime string
		env           func(home, other string) map[string]string
		dataDirOther  bool
		hookDir       func(home string) string
		want          string
	}{
		{name: "DEFENSECLAW_CONFIG names a default config elsewhere", runtime: outageNowStrictConfig,
			env: func(_, other string) map[string]string {
				return map[string]string{"DEFENSECLAW_CONFIG": filepath.Join(other, "config.yaml")}
			}, want: "closed"},
		{name: "DEFENSECLAW_HOME names a default home elsewhere", runtime: outageNowStrictConfig,
			env: func(_, other string) map[string]string { return map[string]string{"DEFENSECLAW_HOME": other} }, want: "closed"},
		{name: "both name a default config elsewhere", runtime: outageNowStrictConfig,
			env: func(_, other string) map[string]string {
				return map[string]string{"DEFENSECLAW_HOME": other, "DEFENSECLAW_CONFIG": filepath.Join(other, "config.yaml")}
			}, want: "closed"},
		// The agent's environment never moves the runtime's data directory
		// either (loadHookRuntimeConfig, the rule hook-data-dir uses too).
		{name: "DEFENSECLAW_CONFIG names this config and DEFENSECLAW_HOME is elsewhere", runtime: outageNowDefaultConfig,
			env: func(home, other string) map[string]string {
				return map[string]string{"DEFENSECLAW_HOME": other, "DEFENSECLAW_CONFIG": filepath.Join(home, "config.yaml")}
			}, want: "open"},
		{name: "the environment names a strict config elsewhere", runtime: outageNowDefaultConfig,
			env: func(_, other string) map[string]string {
				return map[string]string{"DEFENSECLAW_HOME": other, "DEFENSECLAW_CONFIG": filepath.Join(other, "config.yaml")}
			}, want: "open"},
		{name: "the runtime config keeps its data elsewhere", runtime: outageNowDefaultConfig, dataDirOther: true, want: "closed"},
		{name: "relative hook dir", runtime: outageNowDefaultConfig, hookDir: func(string) string { return "hooks" }, want: "closed"},
		{name: "no hook dir", runtime: outageNowDefaultConfig, hookDir: func(string) string { return "" }, want: "closed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			other := t.TempDir()
			t.Setenv("DEFENSECLAW_HOME", "")
			t.Setenv("DEFENSECLAW_CONFIG", "")
			t.Setenv("HOME", home)
			runtimeConfig := tc.runtime
			if tc.dataDirOther {
				runtimeConfig = "data_dir: " + other + "\n" + runtimeConfig
			}
			writeOutageNowConfig(t, home, runtimeConfig)
			otherConfig := outageNowDefaultConfig
			if tc.runtime == outageNowDefaultConfig {
				otherConfig = outageNowStrictConfig
			}
			writeOutageNowConfig(t, other, otherConfig)
			if tc.env != nil {
				for key, value := range tc.env(home, other) {
					t.Setenv(key, value)
				}
			}
			hookDir := filepath.Join(home, "hooks")
			if tc.hookDir != nil {
				hookDir = tc.hookDir(home)
			}
			if got := hookOutageFailModeNow("codex", hookDir); got != tc.want {
				t.Fatalf("hookOutageFailModeNow = %q, want %q", got, tc.want)
			}
		})
	}
}

// A host's managed installation marker is independent of a per-user-looking
// config. A stale per-user hook cannot reopen a managed host's outage.
func TestHookOutageFailModeNowHonorsTheManagedHostMarker(t *testing.T) {
	home := t.TempDir()
	writeOutageNowConfig(t, home, outageNowDefaultConfig)
	marker := filepath.Join(t.TempDir(), "runtime-descriptor")
	oldDescriptor := managedHostDescriptorPath
	oldWindows := managedHostWindowsStandalone
	oldSecureClient := secureClientHost
	oldUncertain := managedHostWindowsMarkerUncertain
	managedHostDescriptorPath = func() string { return marker }
	managedHostWindowsStandalone = func() (string, bool) { return "", false }
	secureClientHost = func() bool { return false }
	managedHostWindowsMarkerUncertain = func() bool { return false }
	t.Cleanup(func() {
		managedHostDescriptorPath = oldDescriptor
		managedHostWindowsStandalone = oldWindows
		secureClientHost = oldSecureClient
		managedHostWindowsMarkerUncertain = oldUncertain
	})
	if got := hookOutageFailModeNow("codex", filepath.Join(home, "hooks")); got != "open" {
		t.Fatalf("absent managed marker: got %q, want open", got)
	}
	if err := os.WriteFile(marker, []byte("managed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := hookOutageFailModeNow("codex", filepath.Join(home, "hooks")); got != "closed" {
		t.Fatalf("present managed marker: got %q, want closed", got)
	}
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(home, "missing-target"), marker); err == nil {
		if got := hookOutageFailModeNow("codex", filepath.Join(home, "hooks")); got != "closed" {
			t.Fatalf("broken managed marker link: got %q, want closed", got)
		}
		if err := os.Remove(marker); err != nil {
			t.Fatal(err)
		}
	}
	if runtime.GOOS != "windows" {
		parent := filepath.Join(t.TempDir(), "not-a-directory")
		if err := os.WriteFile(parent, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		marker = filepath.Join(parent, "runtime-descriptor")
		if got := hookOutageFailModeNow("codex", filepath.Join(home, "hooks")); got != "closed" {
			t.Fatalf("unreadable managed marker path: got %q, want closed", got)
		}
	}
	marker = filepath.Join(t.TempDir(), "runtime-descriptor")
	managedHostWindowsMarkerUncertain = func() bool { return true }
	if got := hookOutageFailModeNow("codex", filepath.Join(home, "hooks")); got != "closed" {
		t.Fatalf("unreadable Windows managed marker: got %q, want closed", got)
	}
	managedHostWindowsMarkerUncertain = oldUncertain
	managedHostWindowsStandalone = func() (string, bool) { return "HKLM managed marker", true }
	if got := hookOutageFailModeNow("codex", filepath.Join(home, "hooks")); got != "closed" {
		t.Fatalf("Windows managed marker: got %q, want closed", got)
	}
	managedHostWindowsStandalone = func() (string, bool) { return "", false }
	secureClientHost = func() bool { return true }
	if got := hookOutageFailModeNow("codex", filepath.Join(home, "hooks")); got != "closed" {
		t.Fatalf("Secure Client marker: got %q, want closed", got)
	}
}

// A per-user native hook whose home comes from the agent's DEFENSECLAW_HOME
// (not the packaged launcher's protected install state) reads that home's
// record for its status, but the agent chose it, so nothing there can open an
// outage: OutageFailModeNow stays unset and the outage closed.
func TestPerUserNativeHookOnAnAgentChosenHomeNeverOpensAnOutage(t *testing.T) {
	home := t.TempDir()
	t.Setenv("DEFENSECLAW_HOME", home)
	t.Setenv("DEFENSECLAW_CONFIG", filepath.Join(home, "config.yaml"))
	t.Setenv("HOME", home)
	writeOutageNowConfig(t, home, outageNowDefaultConfig)
	writeOutageNowConfig(t, filepath.Join(home, "hooks"), "")
	sidecar, err := json.Marshal(map[string]any{
		"version": 2, "gateway_addr": "127.0.0.1:18970",
		"fail_modes": map[string]string{"codex": "open"}, "fail_mode_sources": map[string]string{"codex": "config"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "hooks", ".hookcfg"), sidecar, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, trusted := trustedNativeHookHome(); trusted {
		t.Skip("this test binary runs from a trusted native hook home")
	}
	opts := buildHookOptions("codex", "PreToolUse", "", "")
	if opts.OutageFailModeNow != nil && opts.OutageFailModeNow() == "open" {
		t.Fatal("an agent-chosen DEFENSECLAW_HOME opened the outage")
	}
}

// rel-1-0-6 GAP-0224: `defenseclaw config set data_dir` leaves config.yaml in
// the account's ~/.defenseclaw and the gateway renders the hooks into
// <data_dir>/hooks. A gateway outage then follows that config exactly as with
// the default data_dir: the default tier opens, strict and a saved closed
// close, and a config whose data_dir is another folder, a data directory with
// its own config.yaml, or an account the database does not list keep their
// answer. HOME and DEFENSECLAW_HOME never choose the account's config.
func TestHookOutageFailModeNowFollowsTheAccountConfigOfACustomDataDir(t *testing.T) {
	for _, tc := range []struct {
		name, account, own string
		otherDataDir       bool
		noAccount          bool
		want               string
	}{
		{name: "default tier", account: outageNowDefaultConfig, want: "open"},
		{name: "permissive tier", account: outageNowDefaultConfig + "  rule_pack: permissive\n", want: "open"},
		{name: "strict tier", account: outageNowStrictConfig, want: "closed"},
		{name: "saved closed", account: outageNowDefaultConfig + "  hook_fail_mode: closed\n", want: "closed"},
		// Hooks left in a data dir the account config moved away from
		// follow the folder it names now (movedDataDirOutageMode).
		{name: "account config names another data dir", account: outageNowDefaultConfig, otherDataDir: true, want: "open"},
		{name: "account config names another data dir, strict", account: outageNowStrictConfig, otherDataDir: true, want: "closed"},
		{name: "data dir keeps its own strict config", account: outageNowDefaultConfig, own: outageNowStrictConfig, want: "closed"},
		{name: "account not in the database", account: outageNowDefaultConfig, noAccount: true, want: "closed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			account := t.TempDir()
			dataDir := t.TempDir()
			elsewhere := t.TempDir()
			envHome := t.TempDir()
			oldAccount, oldRoot := outageAccountHome, outageInstalledDataRoot
			outageAccountHome = func() string {
				if tc.noAccount {
					return ""
				}
				return account
			}
			outageInstalledDataRoot = func() (string, bool) { return "", false }
			t.Cleanup(func() { outageAccountHome, outageInstalledDataRoot = oldAccount, oldRoot })
			// The agent's environment names a default-tier home of its own.
			t.Setenv("HOME", envHome)
			t.Setenv("USERPROFILE", envHome)
			t.Setenv("DEFENSECLAW_HOME", filepath.Join(envHome, ".defenseclaw"))
			t.Setenv("DEFENSECLAW_CONFIG", "")
			writeOutageNowConfig(t, filepath.Join(envHome, ".defenseclaw"), "data_dir: "+dataDir+"\n"+outageNowDefaultConfig)
			named := dataDir
			if tc.otherDataDir {
				named = elsewhere
			}
			writeOutageNowConfig(t, filepath.Join(account, ".defenseclaw"), "data_dir: "+named+"\n"+tc.account)
			if tc.own != "" {
				writeOutageNowConfig(t, dataDir, "data_dir: "+dataDir+"\n"+tc.own)
			}
			if err := os.MkdirAll(filepath.Join(dataDir, "hooks"), 0o700); err != nil {
				t.Fatal(err)
			}
			for _, connector := range []string{"claudecode", "codex", "opencode"} {
				if got := hookOutageFailModeNow(connector, filepath.Join(dataDir, "hooks")); got != tc.want {
					t.Fatalf("hookOutageFailModeNow(%s) with data_dir %s = %q, want %q", connector, named, got, tc.want)
				}
			}
		})
	}
}

// rel-1-0-6 GAP-0224 (sweep 8): an agent session started before `defenseclaw
// config set data_dir` keeps running the hooks it loaded, the ones in the
// account's own .defenseclaw (Claude Code keeps its hook commands for the
// session). Their config.yaml is the account's config, now naming the new
// data directory. They get the answer the new folder's hooks get: the
// default and permissive tiers open; strict, a saved closed, an install
// lock in either folder, a strict config.yaml of the new folder, a new
// folder config that names yet another folder and an account the database
// does not list close. The agent's HOME and DEFENSECLAW_HOME never stand in
// for the account's folder.
func TestHookOutageFailModeNowStaleAccountHooksFollowTheMovedDataDir(t *testing.T) {
	lock := func(t *testing.T, root string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Join(root, ".install.lock"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		name, account, moved string
		lockAccount          bool
		lockMoved            bool
		movedElsewhere       bool
		noAccount            bool
		envHomeOnly          bool
		want                 string
	}{
		{name: "default tier", account: outageNowDefaultConfig, want: "open"},
		{name: "permissive tier", account: outageNowDefaultConfig + "  rule_pack: permissive\n", want: "open"},
		{name: "strict tier", account: outageNowStrictConfig, want: "closed"},
		{name: "saved closed", account: outageNowDefaultConfig + "  hook_fail_mode: closed\n", want: "closed"},
		{name: "install holds the account folder", account: outageNowDefaultConfig, lockAccount: true, want: "closed"},
		{name: "install holds the moved folder", account: outageNowDefaultConfig, lockMoved: true, want: "closed"},
		{name: "moved folder keeps its own strict config", account: outageNowDefaultConfig, moved: outageNowStrictConfig, want: "closed"},
		{name: "moved folder config names yet another folder", account: outageNowDefaultConfig, moved: outageNowDefaultConfig, movedElsewhere: true, want: "closed"},
		{name: "account not in the database", account: outageNowDefaultConfig, noAccount: true, want: "closed"},
		{name: "only the agent HOME names the folder", account: outageNowDefaultConfig, envHomeOnly: true, want: "closed"},
		// The account config the left hooks load is a floor (review P2).
		{name: "account strict, moved folder keeps its own default config", account: outageNowStrictConfig, moved: outageNowDefaultConfig, want: "closed"},
		{name: "account saved closed, moved folder keeps its own default config", account: outageNowDefaultConfig + "  hook_fail_mode: closed\n", moved: outageNowDefaultConfig, want: "closed"},
		{name: "account default, moved folder keeps its own default config", account: outageNowDefaultConfig, moved: outageNowDefaultConfig, want: "open"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			account := t.TempDir()
			envHome := t.TempDir()
			moved := t.TempDir()
			elsewhere := t.TempDir()
			oldAccount, oldRoot := outageAccountHome, outageInstalledDataRoot
			outageAccountHome = func() string {
				if tc.noAccount {
					return ""
				}
				if tc.envHomeOnly {
					return t.TempDir()
				}
				return account
			}
			outageInstalledDataRoot = func() (string, bool) { return "", false }
			t.Cleanup(func() { outageAccountHome, outageInstalledDataRoot = oldAccount, oldRoot })
			hooksHome := account
			if tc.envHomeOnly {
				hooksHome = envHome
			}
			t.Setenv("HOME", hooksHome)
			t.Setenv("USERPROFILE", hooksHome)
			t.Setenv("DEFENSECLAW_HOME", filepath.Join(hooksHome, ".defenseclaw"))
			t.Setenv("DEFENSECLAW_CONFIG", "")
			own := filepath.Join(hooksHome, ".defenseclaw")
			writeOutageNowConfig(t, own, "data_dir: "+moved+"\n"+tc.account)
			if tc.moved != "" {
				named := moved
				if tc.movedElsewhere {
					named = elsewhere
				}
				writeOutageNowConfig(t, moved, "data_dir: "+named+"\n"+tc.moved)
			}
			for _, dir := range []string{filepath.Join(own, "hooks"), filepath.Join(moved, "hooks")} {
				if err := os.MkdirAll(dir, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if tc.lockAccount {
				lock(t, own)
			}
			if tc.lockMoved {
				lock(t, moved)
			}
			for _, connector := range []string{"claudecode", "codex", "opencode"} {
				if got := hookOutageFailModeNow(connector, filepath.Join(own, "hooks")); got != tc.want {
					t.Fatalf("stale hooks hookOutageFailModeNow(%s) = %q, want %q", connector, got, tc.want)
				}
			}
		})
	}
}

// The way back (rel-1-0-6 GAP-0224, sweep 8): a session started on a custom
// data_dir keeps its hooks there after `config set data_dir` moves the data
// back to ~/.defenseclaw. That folder has no config.yaml of its own and its
// hooks load the account's config, which now names ~/.defenseclaw: they get
// the account folder's answer. A strict account config, an install lock in
// the left folder or the account folder, and a left folder with a
// config.yaml of its own still close.
func TestHookOutageFailModeNowHooksLeftInAMovedBackDataDirFollowTheAccount(t *testing.T) {
	for _, tc := range []struct {
		name, account, leftOwn string
		lockLeft, lockAccount  bool
		want                   string
	}{
		{name: "default tier", account: outageNowDefaultConfig, want: "open"},
		{name: "strict tier", account: outageNowStrictConfig, want: "closed"},
		{name: "install holds the left folder", account: outageNowDefaultConfig, lockLeft: true, want: "closed"},
		{name: "install holds the account folder", account: outageNowDefaultConfig, lockAccount: true, want: "closed"},
		{name: "left folder keeps a config of its own", account: outageNowDefaultConfig, leftOwn: outageNowDefaultConfig, want: "closed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			account := t.TempDir()
			left := t.TempDir()
			oldAccount, oldRoot := outageAccountHome, outageInstalledDataRoot
			outageAccountHome = func() string { return account }
			outageInstalledDataRoot = func() (string, bool) { return "", false }
			t.Cleanup(func() { outageAccountHome, outageInstalledDataRoot = oldAccount, oldRoot })
			t.Setenv("HOME", account)
			t.Setenv("USERPROFILE", account)
			t.Setenv("DEFENSECLAW_HOME", "")
			t.Setenv("DEFENSECLAW_CONFIG", "")
			own := filepath.Join(account, ".defenseclaw")
			writeOutageNowConfig(t, own, tc.account)
			if tc.leftOwn != "" {
				writeOutageNowConfig(t, left, "data_dir: "+own+"\n"+tc.leftOwn)
			}
			for _, dir := range []string{filepath.Join(own, "hooks"), filepath.Join(left, "hooks")} {
				if err := os.MkdirAll(dir, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			for _, root := range []struct {
				on   bool
				path string
			}{{tc.lockLeft, left}, {tc.lockAccount, own}} {
				if root.on {
					if err := os.MkdirAll(filepath.Join(root.path, ".install.lock"), 0o700); err != nil {
						t.Fatal(err)
					}
				}
			}
			for _, connector := range []string{"claudecode", "codex", "opencode"} {
				if got := hookOutageFailModeNow(connector, filepath.Join(left, "hooks")); got != tc.want {
					t.Fatalf("left hooks hookOutageFailModeNow(%s) = %q, want %q", connector, got, tc.want)
				}
			}
		})
	}
}

// rel-1-0-6 GAP-0224 review: a data directory's own config.yaml no longer
// outranks the account's config that names it. The gateway enforces the
// account's config, so its strict tier, a saved closed or a managed mode
// closes the outage of the fresh hooks of that folder too; a default
// account config, or one that names another folder, leaves the folder's own
// config the answer. An account config this release cannot load closes when
// its plain data_dir names the folder.
func TestHookOutageFailModeNowAccountConfigIsAFloorForTheDataDirItNames(t *testing.T) {
	for _, tc := range []struct {
		name, account, own string
		namesOther         bool
		want               string
	}{
		{name: "account default, own default", account: outageNowDefaultConfig, own: outageNowDefaultConfig, want: "open"},
		{name: "account strict, own default", account: outageNowStrictConfig, own: outageNowDefaultConfig, want: "closed"},
		{name: "account saved closed, own default", account: outageNowDefaultConfig + "  hook_fail_mode: closed\n", own: outageNowDefaultConfig, want: "closed"},
		{name: "account connector strict, own default", account: outageNowDefaultConfig + "  connectors:\n    claudecode:\n      rule_pack: strict\n", own: outageNowDefaultConfig, want: "closed"},
		{name: "account strict names another folder, own default", account: outageNowStrictConfig, own: outageNowDefaultConfig, namesOther: true, want: "open"},
		{name: "account config this release cannot load names the folder", account: "config_version: 7\nguardrail:\n  mode: observe\n", own: outageNowDefaultConfig, want: "closed"},
		{name: "account config this release cannot load names another folder", account: "config_version: 7\nguardrail:\n  mode: observe\n", own: outageNowDefaultConfig, namesOther: true, want: "open"},
		{name: "account default, own strict", account: outageNowDefaultConfig, own: outageNowStrictConfig, want: "closed"},
		// Review 2 P4: a managed or Secure Client account config closes even
		// with a saved admin open.
		{name: "account managed with saved open, own default", account: "config_version: 9\ndeployment_mode: managed_enterprise\nenterprise:\n  profile: standalone\nobservability: {}\nguardrail:\n  mode: observe\n  hook_fail_mode: open\n", own: outageNowDefaultConfig, want: "closed"},
		{name: "account Secure Client, own default", account: "config_version: 9\ndeployment_mode: managed_enterprise\nenterprise:\n  profile: secure_client\nobservability: {}\nguardrail:\n  mode: observe\n  hook_fail_mode: open\n", own: outageNowDefaultConfig, want: "closed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			account := t.TempDir()
			dataDir := t.TempDir()
			other := t.TempDir()
			oldAccount, oldRoot := outageAccountHome, outageInstalledDataRoot
			outageAccountHome = func() string { return account }
			outageInstalledDataRoot = func() (string, bool) { return "", false }
			t.Cleanup(func() { outageAccountHome, outageInstalledDataRoot = oldAccount, oldRoot })
			t.Setenv("HOME", account)
			t.Setenv("USERPROFILE", account)
			t.Setenv("DEFENSECLAW_HOME", "")
			t.Setenv("DEFENSECLAW_CONFIG", "")
			named := dataDir
			if tc.namesOther {
				named = other
			}
			writeOutageNowConfig(t, filepath.Join(account, ".defenseclaw"), "data_dir: "+named+"\n"+tc.account)
			writeOutageNowConfig(t, dataDir, "data_dir: "+dataDir+"\n"+tc.own)
			if err := os.MkdirAll(filepath.Join(dataDir, "hooks"), 0o700); err != nil {
				t.Fatal(err)
			}
			if got := hookOutageFailModeNow("claudecode", filepath.Join(dataDir, "hooks")); got != tc.want {
				t.Fatalf("hookOutageFailModeNow = %q, want %q", got, tc.want)
			}
		})
	}
}

// rel-1-0-6 GAP-0224 review P4: the closing conditions of the moved branch
// that had no row. (1) On Windows the installed runtime's protected data
// root is tried first (hookRuntimeConfigPath): hooks left in a folder with no
// config.yaml that load that root's config, not the account database's
// .defenseclaw, stay closed (a custom install.ps1 DEFENSECLAW_HOME is a
// documented residual). (2) An install window leaves out only the install
// lock, also in the moved folder the answer recurses into.
func TestHookOutageFailModeNowMovedBranchInstalledRootAndInstallWindow(t *testing.T) {
	// GAP-0307: the installed root is one of the account's own folders, so
	// hooks left in a folder with no config.yaml that load its config
	// follow the folder it names.
	t.Run("left hooks load the installed root's config", func(t *testing.T) {
		account := t.TempDir()
		root := t.TempDir()
		left := t.TempDir()
		moved := t.TempDir()
		oldAccount, oldRoot := outageAccountHome, outageInstalledDataRoot
		outageAccountHome = func() string { return account }
		outageInstalledDataRoot = func() (string, bool) { return root, true }
		t.Cleanup(func() { outageAccountHome, outageInstalledDataRoot = oldAccount, oldRoot })
		t.Setenv("HOME", account)
		t.Setenv("USERPROFILE", account)
		t.Setenv("DEFENSECLAW_HOME", "")
		t.Setenv("DEFENSECLAW_CONFIG", "")
		writeOutageNowConfig(t, root, "data_dir: "+moved+"\n"+outageNowDefaultConfig)
		for _, dir := range []string{filepath.Join(left, "hooks"), filepath.Join(moved, "hooks")} {
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
		}
		if got := hookOutageFailModeNow("claudecode", filepath.Join(left, "hooks")); got != "open" {
			t.Fatalf("left hooks under the installed root's config = %q, want open", got)
		}
		writeOutageNowConfig(t, root, "data_dir: "+moved+"\n"+outageNowStrictConfig)
		if got := hookOutageFailModeNow("claudecode", filepath.Join(left, "hooks")); got != "closed" {
			t.Fatalf("left hooks under the installed root's strict config = %q, want closed", got)
		}
	})
	t.Run("install window over a lock in the moved folder", func(t *testing.T) {
		account := t.TempDir()
		moved := t.TempDir()
		oldAccount, oldRoot := outageAccountHome, outageInstalledDataRoot
		outageAccountHome = func() string { return account }
		outageInstalledDataRoot = func() (string, bool) { return "", false }
		t.Cleanup(func() { outageAccountHome, outageInstalledDataRoot = oldAccount, oldRoot })
		t.Setenv("HOME", account)
		t.Setenv("USERPROFILE", account)
		t.Setenv("DEFENSECLAW_HOME", "")
		t.Setenv("DEFENSECLAW_CONFIG", "")
		own := filepath.Join(account, ".defenseclaw")
		writeOutageNowConfig(t, own, "data_dir: "+moved+"\n"+outageNowDefaultConfig)
		for _, dir := range []string{filepath.Join(own, "hooks"), filepath.Join(moved, "hooks"), filepath.Join(moved, ".install.lock")} {
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
		}
		if got := hookOutageFailModeFor("claudecode", filepath.Join(own, "hooks"), true); got != "open" {
			t.Fatalf("install window, lock in the moved folder = %q, want open", got)
		}
		if got := hookOutageFailModeFor("claudecode", filepath.Join(own, "hooks"), false); got != "closed" {
			t.Fatalf("no install window, lock in the moved folder = %q, want closed", got)
		}
	})
}

// Review 2 P4 and rel-1-0-6 GAP-0309 (Windows shape, the installed data root
// stubbed): (1) a strict config of the installed root that names the hooks'
// data dir is a floor over the folder's own default config; (2) the installed
// root comes from a state file the user owns on a PowerShell install, so
// when it points the hooks at a folder with its own default config, the
// account database's strict config still closes, whatever folder it names.
// A default or absent account config leaves the folder's answer.
func TestHookOutageFailModeNowInstalledRootPointerNeverOutranksTheAccountConfig(t *testing.T) {
	for _, tc := range []struct {
		name, rootConfig, account string
		rootNamesData             bool
		want                      string
	}{
		{name: "root strict names the data dir, own default", rootConfig: outageNowStrictConfig, rootNamesData: true, want: "closed"},
		{name: "root default names the data dir, own default", rootConfig: outageNowDefaultConfig, rootNamesData: true, want: "open"},
		{name: "pointer to a default folder, account strict", account: outageNowStrictConfig, want: "closed"},
		{name: "pointer to a default folder, account saved closed", account: outageNowDefaultConfig + "  hook_fail_mode: closed\n", want: "closed"},
		{name: "pointer to a default folder, account default", account: outageNowDefaultConfig, want: "open"},
		{name: "pointer to a default folder, no account config", want: "open"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			account := t.TempDir()
			root := t.TempDir()
			oldAccount, oldRoot := outageAccountHome, outageInstalledDataRoot
			outageAccountHome = func() string { return account }
			t.Cleanup(func() { outageAccountHome, outageInstalledDataRoot = oldAccount, oldRoot })
			t.Setenv("HOME", account)
			t.Setenv("USERPROFILE", account)
			t.Setenv("DEFENSECLAW_HOME", "")
			t.Setenv("DEFENSECLAW_CONFIG", "")
			if tc.account != "" {
				writeOutageNowConfig(t, filepath.Join(account, ".defenseclaw"), tc.account)
			}
			dataDir := root
			if tc.rootNamesData {
				// The installed root's config names another data dir that
				// keeps a default config of its own.
				dataDir = t.TempDir()
				writeOutageNowConfig(t, root, "data_dir: "+dataDir+"\n"+tc.rootConfig)
			}
			writeOutageNowConfig(t, dataDir, "data_dir: "+dataDir+"\n"+outageNowDefaultConfig)
			outageInstalledDataRoot = func() (string, bool) { return root, true }
			if err := os.MkdirAll(filepath.Join(dataDir, "hooks"), 0o700); err != nil {
				t.Fatal(err)
			}
			if got := hookOutageFailModeNow("claudecode", filepath.Join(dataDir, "hooks")); got != tc.want {
				t.Fatalf("hookOutageFailModeNow = %q, want %q", got, tc.want)
			}
		})
	}
}
