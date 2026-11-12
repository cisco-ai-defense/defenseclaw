//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/pelletier/go-toml/v2"
)

// The Linux and macOS guardian workers share this path. A policy-only mode
// change must leave an already-correct Hermes target untouched, while a
// changed hook still receives a repair on the next pass.
func TestGAP0638GAP0642ManagedHermesModeOnlyEnsureKeepsTarget(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("the standalone worker runs as the account")
	}
	previousStandalone := enterprisehooks.StandaloneUnix()
	enterprisehooks.SetStandaloneUnix(true)
	t.Cleanup(func() { enterprisehooks.SetStandaloneUnix(previousStandalone) })
	home := t.TempDir()
	t.Setenv("HOME", home)
	configDir := filepath.Join(home, ".hermes")
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "config.yaml"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	opts := enterprisehooks.InstallOptions{
		ConnectorName: "hermes", UserHome: home, OwnerUID: os.Getuid(), OwnerGID: os.Getgid(),
		APIAddr: "127.0.0.1:18970", ProxyAddr: "127.0.0.1:4000",
		APIToken: strings.Repeat("a", 64), OTLPPathToken: strings.Repeat("d", 64),
		GuardrailMode: "observe", HookFailMode: "closed", AgentVersion: "0.21.5",
	}
	if _, err := enterprisehooks.Install(context.Background(), opts); err != nil {
		t.Fatalf("initial Hermes install: %v", err)
	}
	dataDir := filepath.Join(home, ".defenseclaw")
	lockPath := filepath.Join(dataDir, "hook_contract_lock.json")
	scriptPath := filepath.Join(dataDir, "hooks", "hermes-hook.sh")
	lockBefore, err := os.ReadFile(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	scriptBefore, err := os.Stat(scriptPath)
	if err != nil {
		t.Fatal(err)
	}
	opts.GuardrailMode = "action"
	opts.AllowMissingHookConfigRepair = true
	request := enterpriseHookWorkerRequest{
		Operation: enterpriseHookWorkerOpApply, Standalone: true,
		Targets: []enterpriseHookWorkerTarget{{
			Index: 0, Mode: enterpriseHookWorkerModeVerifyOrRepair, PreviouslyProtected: true,
			Options: enterpriseHookWorkerOptionsFrom(opts),
		}},
	}
	response := runEnterpriseHookWorkerApply(context.Background(), request)
	if len(response.Targets) != 1 || !response.Targets[0].OK || response.Targets[0].Repaired {
		t.Fatalf("%s mode-only ensure reported repair: %+v", runtime.GOOS, response.Targets)
	}
	lockAfter, err := os.ReadFile(lockPath)
	if err != nil || string(lockAfter) != string(lockBefore) {
		t.Fatalf("mode-only ensure changed the contract lock: equal=%t err=%v", string(lockAfter) == string(lockBefore), err)
	}
	scriptAfter, err := os.Stat(scriptPath)
	if err != nil || !os.SameFile(scriptBefore, scriptAfter) || !scriptBefore.ModTime().Equal(scriptAfter.ModTime()) {
		t.Fatalf("mode-only ensure rewrote the Hermes hook: same=%t err=%v", err == nil && os.SameFile(scriptBefore, scriptAfter), err)
	}
	if err := os.Chmod(scriptPath, 0o744); err != nil {
		t.Fatal(err)
	}
	response = runEnterpriseHookWorkerApply(context.Background(), request)
	if len(response.Targets) != 1 || !response.Targets[0].OK || !response.Targets[0].Repaired {
		t.Fatalf("changed Hermes permissions were not repaired: %+v", response.Targets)
	}
	if info, err := os.Stat(scriptPath); err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("Hermes hook mode after repair: info=%v err=%v", info, err)
	}
	if err := os.WriteFile(scriptPath, []byte("changed hook\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	response = runEnterpriseHookWorkerApply(context.Background(), request)
	if len(response.Targets) != 1 || !response.Targets[0].OK || !response.Targets[0].Repaired {
		t.Fatalf("changed Hermes hook was not repaired: %+v", response.Targets)
	}
}

func TestGAP0638GAP0642PolicyRerenderIsNotReportedAsDamage(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("the standalone worker runs as the account")
	}
	previousStandalone := enterprisehooks.StandaloneUnix()
	enterprisehooks.SetStandaloneUnix(true)
	t.Cleanup(func() { enterprisehooks.SetStandaloneUnix(previousStandalone) })
	for _, tc := range []struct {
		name, changedPath                                   string
		changedMode                                         os.FileMode
		endpointChange, tokenChange, tokenDrift, wantRepair bool
	}{
		{name: "policy only"},
		{name: "policy and changed hook", changedPath: "kiro-hook.sh", wantRepair: true},
		{name: "policy and disabled hook", changedPath: "kiro-hook.sh", changedMode: 0o600, wantRepair: true},
		{name: "policy and changed helper permissions", changedPath: "_hardening.sh", changedMode: 0o644, wantRepair: true},
		{name: "policy and endpoint", endpointChange: true},
		{name: "policy and credential rotation", tokenChange: true},
		{name: "policy and changed installed credential", tokenDrift: true, wantRepair: true},
		{name: "policy and endpoint with changed hook", changedPath: "kiro-hook.sh", endpointChange: true, wantRepair: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			opts := enterprisehooks.InstallOptions{
				ConnectorName: "kiro", UserHome: home, OwnerUID: os.Getuid(), OwnerGID: os.Getgid(),
				APIAddr: "127.0.0.1:18970", ProxyAddr: "127.0.0.1:4000",
				APIToken: strings.Repeat("a", 64), OTLPPathToken: strings.Repeat("d", 64),
				HookCredentialIdentity: "fixture-account",
				GuardrailMode:          "observe", HookFailMode: "open", AgentVersion: "2.27.1",
			}
			if _, err := enterprisehooks.Install(context.Background(), opts); err != nil {
				t.Fatalf("initial Kiro install: %v", err)
			}
			if tc.changedPath != "" {
				path := filepath.Join(home, ".defenseclaw", "hooks", tc.changedPath)
				if tc.changedMode != 0 {
					if err := os.Chmod(path, tc.changedMode); err != nil {
						t.Fatal(err)
					}
				} else if err := os.WriteFile(path, []byte("changed hook\n"), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			opts.GuardrailMode, opts.HookFailMode = "action", "closed"
			if tc.endpointChange {
				opts.APIAddr = "127.0.0.1:18971"
			}
			if tc.tokenChange {
				opts.APIToken = strings.Repeat("b", 64)
			}
			if tc.tokenDrift {
				path, err := connector.HookAPITokenFilePath(filepath.Join(home, ".defenseclaw"), "kiro")
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(strings.Repeat("b", 64)+"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			opts.AllowMissingHookConfigRepair = true
			request := enterpriseHookWorkerRequest{
				Operation: enterpriseHookWorkerOpApply, Standalone: true,
				Targets: []enterpriseHookWorkerTarget{{
					Index: 0, Mode: enterpriseHookWorkerModeVerifyOrRepair, PreviouslyProtected: true,
					Options: enterpriseHookWorkerOptionsFrom(opts),
				}},
			}
			response := runEnterpriseHookWorkerApply(context.Background(), request)
			if len(response.Targets) != 1 || !response.Targets[0].OK || response.Targets[0].Repaired != tc.wantRepair {
				t.Fatalf("policy reconciliation classification = %+v, want repaired=%t", response.Targets, tc.wantRepair)
			}
			if _, err := enterprisehooks.Verify(context.Background(), opts); err != nil {
				t.Fatalf("reconciled Kiro runtime did not verify: %v", err)
			}
		})
	}
}

func TestGAP0638GAP0642PluginEndpointChangeKeepsRepairClassification(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("the standalone worker runs as the account")
	}
	previousStandalone := enterprisehooks.StandaloneUnix()
	enterprisehooks.SetStandaloneUnix(true)
	t.Cleanup(func() { enterprisehooks.SetStandaloneUnix(previousStandalone) })
	home := t.TempDir()
	t.Setenv("HOME", home)
	plugin := filepath.Join(home, ".config", "amp", "plugins", "defenseclaw.ts")
	if err := os.MkdirAll(filepath.Dir(plugin), 0o700); err != nil {
		t.Fatal(err)
	}
	previousPlugin := connector.AMPPluginPathOverride
	connector.AMPPluginPathOverride = plugin
	t.Cleanup(func() { connector.AMPPluginPathOverride = previousPlugin })
	opts := enterprisehooks.InstallOptions{
		ConnectorName: "amp", UserHome: home, OwnerUID: os.Getuid(), OwnerGID: os.Getgid(),
		APIAddr: "127.0.0.1:18970", ProxyAddr: "127.0.0.1:4000",
		APIToken: strings.Repeat("a", 64), OTLPPathToken: strings.Repeat("d", 64),
		HookCredentialIdentity: "fixture-account",
		GuardrailMode:          "observe", HookFailMode: "open", AgentVersion: "0.0.1785334225",
	}
	if _, err := enterprisehooks.Install(context.Background(), opts); err != nil {
		t.Fatalf("initial Amp install: %v", err)
	}
	opts.GuardrailMode, opts.HookFailMode = "action", "closed"
	opts.APIAddr = "127.0.0.1:18971"
	opts.AllowMissingHookConfigRepair = true
	request := enterpriseHookWorkerRequest{
		Operation: enterpriseHookWorkerOpApply, Standalone: true,
		Targets: []enterpriseHookWorkerTarget{{Index: 0, Mode: enterpriseHookWorkerModeVerifyOrRepair,
			PreviouslyProtected: true, Options: enterpriseHookWorkerOptionsFrom(opts)}},
	}
	response := runEnterpriseHookWorkerApply(context.Background(), request)
	if len(response.Targets) != 1 || !response.Targets[0].OK || response.Targets[0].Repaired {
		t.Fatalf("Amp endpoint reconciliation reported repair: %+v", response.Targets)
	}
	if _, err := enterprisehooks.Verify(context.Background(), opts); err != nil {
		t.Fatalf("Amp endpoint reconciliation did not verify: %v", err)
	}
	if err := os.Chmod(plugin, 0o644); err != nil {
		t.Fatal(err)
	}
	opts.APIAddr = "127.0.0.1:18972"
	request.Targets[0].Options = enterpriseHookWorkerOptionsFrom(opts)
	response = runEnterpriseHookWorkerApply(context.Background(), request)
	if len(response.Targets) != 1 || !response.Targets[0].OK || !response.Targets[0].Repaired {
		t.Fatalf("changed Amp plugin permissions were not reported as repair: %+v", response.Targets)
	}
	if info, err := os.Stat(plugin); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("Amp plugin mode after repair: info=%v err=%v", info, err)
	}
	if err := os.WriteFile(plugin, []byte("changed plugin\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	opts.APIAddr = "127.0.0.1:18973"
	request.Targets[0].Options = enterpriseHookWorkerOptionsFrom(opts)
	response = runEnterpriseHookWorkerApply(context.Background(), request)
	if len(response.Targets) != 1 || !response.Targets[0].OK || !response.Targets[0].Repaired {
		t.Fatalf("changed Amp plugin was not reported as repair: %+v", response.Targets)
	}
}

// gap0638CredentialFixture installs connectorName the way the standalone
// Unix guardian does: socket transport, a numeric account identity and both
// scoped credentials bound in the lock.
func gap0638CredentialFixture(t *testing.T, connectorName string) (string, enterprisehooks.InstallOptions) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("CODEX_HOME", "")
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	opts := enterprisehooks.InstallOptions{
		ConnectorName: connectorName, UserHome: home, OwnerUID: os.Getuid(), OwnerGID: os.Getgid(),
		APIAddr: "127.0.0.1:18970", ProxyAddr: "127.0.0.1:4000",
		APIToken: strings.Repeat("a", 64), OTLPPathToken: strings.Repeat("d", 64),
		HookCredentialIdentity: strconv.Itoa(os.Getuid()),
		GuardrailMode:          "observe", HookFailMode: "closed",
		ManagedHookSocket: "/var/run/defenseclaw/hook.sock", ManagedServiceUID: 461,
	}
	switch connectorName {
	case "codex":
		opts.AgentVersion = "codex-cli 0.142.0"
		if err := os.MkdirAll(filepath.Join(home, ".codex"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(home, ".codex", "config.toml"), []byte("model = \"gpt-5\"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	case "claudecode":
		opts.AgentVersion = "2.1.187 (Claude Code)"
		if err := os.MkdirAll(filepath.Join(home, ".claude"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(home, ".claude", "settings.json"), []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := enterprisehooks.Install(context.Background(), opts); err != nil {
		t.Fatalf("initial %s install: %v", connectorName, err)
	}
	if _, err := enterprisehooks.Verify(context.Background(), opts); err != nil {
		t.Fatalf("initial %s runtime does not verify: %v", connectorName, err)
	}
	return home, opts
}

// gap0638Reconcile runs one guardian pass for opts. prior is what the
// guardian passes while it holds a credential rotation.
func gap0638Reconcile(t *testing.T, opts enterprisehooks.InstallOptions, prior *enterprisehooks.HookCredentials) enterpriseHookWorkerTargetResult {
	t.Helper()
	opts.AllowMissingHookConfigRepair = true
	request := enterpriseHookWorkerRequest{
		Operation: enterpriseHookWorkerOpApply, Standalone: true,
		Targets: []enterpriseHookWorkerTarget{{Index: 0, Mode: enterpriseHookWorkerModeVerifyOrRepair,
			PreviouslyProtected: true, Options: enterpriseHookWorkerOptionsFrom(opts), PriorCredentials: prior}},
	}
	response := runEnterpriseHookWorkerApply(context.Background(), request)
	if len(response.Targets) != 1 || !response.Targets[0].OK {
		t.Fatalf("reconciliation failed: %+v", response.Targets)
	}
	if _, err := enterprisehooks.Verify(context.Background(), opts); err != nil {
		t.Fatalf("reconciled runtime does not verify: %v", err)
	}
	return response.Targets[0]
}

// The guardian rotates the per-user API and OTLP credentials together and
// passes the prior pair while it holds the rotation. The prior state is
// checked with both prior credentials: a rotation on its own is
// configuration, while an independently changed DefenseClaw hook, installed
// credential, or a pair the lock does not record stays a repair (the HIGH
// connector-hook-repaired row).
func TestGAP0638GAP0642CredentialRotationIsNotReportedAsRepair(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("the standalone worker runs as the account")
	}
	previousStandalone := enterprisehooks.StandaloneUnix()
	enterprisehooks.SetStandaloneUnix(true)
	t.Cleanup(func() { enterprisehooks.SetStandaloneUnix(previousStandalone) })
	for _, connectorName := range []string{"codex", "claudecode"} {
		for _, tc := range []struct {
			name                                             string
			api, otlp, mode, noPrior, wrongPrior, wantRepair bool
			change                                           func(t *testing.T, dataDir, script string)
		}{
			{name: "both credentials rotate", api: true, otlp: true},
			{name: "mode and both credentials rotate", api: true, otlp: true, mode: true},
			{name: "API credential rotates", api: true},
			{name: "OTLP credential rotates", otlp: true},
			{name: "mode only", mode: true},
			{name: "both credentials change without a held rotation", api: true, otlp: true, noPrior: true, wantRepair: true},
			{name: "rotation whose prior pair the lock does not record", api: true, otlp: true, wrongPrior: true, wantRepair: true},
			{name: "rotation and changed installed API credential", api: true, otlp: true, wantRepair: true,
				change: func(t *testing.T, dataDir, _ string) {
					path, err := connector.HookAPITokenFilePath(dataDir, connectorName)
					if err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(path, []byte(strings.Repeat("c", 64)+"\n"), 0o600); err != nil {
						t.Fatal(err)
					}
				}},
			{name: "rotation and changed hook script", api: true, otlp: true, wantRepair: true,
				change: func(t *testing.T, _, script string) {
					if err := os.WriteFile(script, []byte("changed hook\n"), 0o700); err != nil {
						t.Fatal(err)
					}
				}},
			{name: "rotation and changed hook script mode", api: true, otlp: true, mode: true, wantRepair: true,
				change: func(t *testing.T, _, script string) {
					if err := os.Chmod(script, 0o744); err != nil {
						t.Fatal(err)
					}
				}},
		} {
			t.Run(connectorName+"/"+tc.name, func(t *testing.T) {
				home, opts := gap0638CredentialFixture(t, connectorName)
				dataDir := filepath.Join(home, ".defenseclaw")
				conn, ok := connector.NewDefaultRegistry().Get(connectorName)
				if !ok {
					t.Fatalf("connector %s is not registered", connectorName)
				}
				owner, ok := conn.(interface {
					HookScriptNames(connector.SetupOpts) []string
				})
				if !ok || len(owner.HookScriptNames(connector.SetupOpts{})) == 0 {
					t.Fatalf("connector %s has no hook script", connectorName)
				}
				script := filepath.Join(dataDir, "hooks", owner.HookScriptNames(connector.SetupOpts{})[0])
				if tc.change != nil {
					tc.change(t, dataDir, script)
				}
				prior := &enterprisehooks.HookCredentials{APIToken: opts.APIToken, OTLPPathToken: opts.OTLPPathToken}
				if tc.wrongPrior {
					prior.OTLPPathToken = strings.Repeat("f", 64)
				}
				if tc.noPrior {
					prior = nil
				}
				if tc.api {
					opts.APIToken = strings.Repeat("b", 64)
				}
				if tc.otlp {
					opts.OTLPPathToken = strings.Repeat("e", 64)
				}
				if tc.mode {
					opts.GuardrailMode = "action"
				}
				if got := gap0638Reconcile(t, opts, prior); got.Repaired != tc.wantRepair {
					t.Fatalf("%s %s: repaired=%t, want %t", connectorName, tc.name, got.Repaired, tc.wantRepair)
				}
			})
		}
	}
}

// Only the DefenseClaw-owned parts of the Codex configuration decide a
// repair. The model, an unrelated key and the vendor login are the user's;
// a DefenseClaw hook entry that was removed or edited is a repair.
func TestGAP0638GAP0642CodexVendorFieldsDoNotDecideRepair(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("the standalone worker runs as the account")
	}
	previousStandalone := enterprisehooks.StandaloneUnix()
	enterprisehooks.SetStandaloneUnix(true)
	t.Cleanup(func() { enterprisehooks.SetStandaloneUnix(previousStandalone) })
	editConfig := func(t *testing.T, home string, edit func(cfg map[string]any)) {
		t.Helper()
		path := filepath.Join(home, ".codex", "config.toml")
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		cfg := map[string]any{}
		if err := toml.Unmarshal(raw, &cfg); err != nil {
			t.Fatal(err)
		}
		edit(cfg)
		out, err := toml.Marshal(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, out, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var replaceHookCommand func(v any) any
	replaceHookCommand = func(v any) any {
		switch value := v.(type) {
		case string:
			if strings.Contains(value, "codex-hook.sh") {
				return "/bin/true"
			}
		case map[string]any:
			for key, item := range value {
				value[key] = replaceHookCommand(item)
			}
		case []any:
			for i, item := range value {
				value[i] = replaceHookCommand(item)
			}
		}
		return v
	}
	for _, tc := range []struct {
		name               string
		rotate, wantRepair bool
		change             func(t *testing.T, home string)
	}{
		{name: "model change", change: func(t *testing.T, home string) {
			editConfig(t, home, func(cfg map[string]any) { cfg["model"] = "gpt-5.5" })
		}},
		{name: "model change with rotation", rotate: true, change: func(t *testing.T, home string) {
			editConfig(t, home, func(cfg map[string]any) { cfg["model"] = "gpt-5.5" })
		}},
		{name: "unrelated key with rotation", rotate: true, change: func(t *testing.T, home string) {
			editConfig(t, home, func(cfg map[string]any) { cfg["approval_policy"] = "on-request" })
		}},
		{name: "vendor login rotation with rotation", rotate: true, change: func(t *testing.T, home string) {
			if err := os.WriteFile(filepath.Join(home, ".codex", "auth.json"), []byte("{\"OPENAI_API_KEY\":\"fixture-rotated\"}\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "hook entry removed", wantRepair: true, change: func(t *testing.T, home string) {
			editConfig(t, home, func(cfg map[string]any) { delete(cfg, "hooks") })
		}},
		{name: "hook entry removed with rotation", rotate: true, wantRepair: true, change: func(t *testing.T, home string) {
			editConfig(t, home, func(cfg map[string]any) { delete(cfg, "hooks") })
		}},
		{name: "hook entry edited with rotation", rotate: true, wantRepair: true, change: func(t *testing.T, home string) {
			editConfig(t, home, func(cfg map[string]any) { cfg["hooks"] = replaceHookCommand(cfg["hooks"]) })
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home, opts := gap0638CredentialFixture(t, "codex")
			tc.change(t, home)
			opts.GuardrailMode = "action"
			var prior *enterprisehooks.HookCredentials
			if tc.rotate {
				prior = &enterprisehooks.HookCredentials{APIToken: opts.APIToken, OTLPPathToken: opts.OTLPPathToken}
				opts.APIToken, opts.OTLPPathToken = strings.Repeat("b", 64), strings.Repeat("e", 64)
			}
			if got := gap0638Reconcile(t, opts, prior); got.Repaired != tc.wantRepair {
				t.Fatalf("Codex %s: repaired=%t, want %t", tc.name, got.Repaired, tc.wantRepair)
			}
		})
	}
}

// The guardian passes the pair from the rotation key a run does not render
// from, and none when the keys on disk are not the transaction's.
func TestGAP0638GAP0642PriorCredentialKeyFollowsTheRotationPhase(t *testing.T) {
	committed, staged := strings.Repeat("1", 64), strings.Repeat("2", 64)
	transaction := enterprisehooks.CredentialTransaction{
		Phase:         enterprisehooks.CredentialPhasePrepare,
		PreviousKeyID: connector.UserScopedTokenKeyFingerprint(committed),
		NextKeyID:     connector.UserScopedTokenKeyFingerprint(staged),
	}
	if got := enterpriseHookPriorUserTokenKey(transaction, committed, staged); got != committed {
		t.Fatalf("prepare: prior key is not the committed key")
	}
	transaction.Phase = enterprisehooks.CredentialPhaseRollback
	if got := enterpriseHookPriorUserTokenKey(transaction, committed, staged); got != staged {
		t.Fatalf("rollback: prior key is not the staged key")
	}
	other := strings.Repeat("3", 64)
	for _, keys := range [][2]string{{committed, ""}, {"", staged}, {other, staged}, {committed, other}, {staged, committed}} {
		if got := enterpriseHookPriorUserTokenKey(transaction, keys[0], keys[1]); got != "" {
			t.Fatalf("keys outside the transaction selected a prior key")
		}
	}
}

// gap0638RotationLayout lays out the guardian view of a credential rotation
// under a managed data directory: the committed key, the staged key, and the
// root-only transaction record in the given phase. For the rollback phase
// afterRename moves the staged key aside as the retiring key, the step the
// lifecycle performs before it moves the users back (retireStagedKey).
func gap0638RotationLayout(t *testing.T, committed, staged, phase string, afterRename bool) string {
	t.Helper()
	stubEnterpriseHookAuthorizationTrustForTempDir(t)
	dataDir := filepath.Join(t.TempDir(), "data")
	hooks := filepath.Join(dataDir, "hooks")
	authDir := managed.HookGuardianAuthorizationDir(dataDir)
	for _, dir := range []string{dataDir, hooks, authDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(hooks, ".user-scoped-token.key"), []byte(committed+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stagedPath := filepath.Join(hooks, ".user-scoped-token.key.next")
	if err := os.WriteFile(stagedPath, []byte(staged+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if afterRename {
		retiring, err := connector.RetiringUserScopedTokenKeyPath(dataDir)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(stagedPath, retiring); err != nil {
			t.Fatal(err)
		}
	}
	if phase != "" {
		record, err := json.Marshal(enterprisehooks.CredentialTransaction{
			Version: enterprisehooks.CredentialTransactionVersion, OperationID: strings.Repeat("0", 32), Phase: phase,
			ManifestSHA256: strings.Repeat("d", 64), PreviousKeyID: connector.UserScopedTokenKeyFingerprint(committed),
			NextKeyID: connector.UserScopedTokenKeyFingerprint(staged),
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(authDir, managed.HookGuardianCredentialTransactionFile), record, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dataDir
}

func gap0638KeyPair(t *testing.T, key, connectorName, identity string) enterprisehooks.HookCredentials {
	t.Helper()
	api, err := connector.UserScopedHookAPIToken(key, connectorName, identity)
	if err != nil {
		t.Fatal(err)
	}
	pair := enterprisehooks.HookCredentials{APIToken: api}
	if scope, ok := connector.OTLPPathTokenScopeForConnector(connectorName); ok {
		if pair.OTLPPathToken, err = connector.UserScopedOTLPPathToken(key, scope, identity); err != nil {
			t.Fatal(err)
		}
	}
	return pair
}

// The guardian reads the prior pair from the key files as the rotation
// leaves them. A rollback renames the staged key to the retiring file before
// the users are moved back, so the pair must be found there as well as at the
// staged path; a key that is not the transaction next key, or a phase that
// does not call for it, yields none.
func TestGAP0638GAP0642PriorCredentialsAreReadFromWhereThePhaseKeepsTheKey(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("the key custody checks run as the account")
	}
	committed, staged, other := strings.Repeat("1a", 32), strings.Repeat("2b", 32), strings.Repeat("3c", 32)
	identity := strconv.Itoa(os.Getuid())
	for _, tc := range []struct {
		name        string
		phase       string
		afterRename bool
		nextOnDisk  string
		wantKey     string
	}{
		{name: "prepare uses the committed key", phase: enterprisehooks.CredentialPhasePrepare, wantKey: committed},
		{name: "rollback before the rename uses the staged key", phase: enterprisehooks.CredentialPhaseRollback, wantKey: staged},
		{name: "rollback after the rename uses the retiring key", phase: enterprisehooks.CredentialPhaseRollback, afterRename: true, wantKey: staged},
		{name: "prepare ignores a retiring key", phase: enterprisehooks.CredentialPhasePrepare, afterRename: true},
		{name: "rollback ignores a retiring key that is not the transaction key", phase: enterprisehooks.CredentialPhaseRollback, afterRename: true, nextOnDisk: other},
		{name: "no transaction supplies none", afterRename: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dataDir := gap0638RotationLayout(t, committed, staged, tc.phase, tc.afterRename)
			if tc.nextOnDisk != "" {
				retiring, _ := connector.RetiringUserScopedTokenKeyPath(dataDir)
				if err := os.WriteFile(retiring, []byte(tc.nextOnDisk+"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			for _, connectorName := range []string{"codex", "claudecode"} {
				got := enterpriseHookPriorUserTokens(dataDir, connectorName, identity)
				if tc.wantKey == "" {
					if got != nil {
						t.Fatalf("%s: a prior pair was supplied", connectorName)
					}
					continue
				}
				if want := gap0638KeyPair(t, tc.wantKey, connectorName, identity); got == nil || *got != want {
					t.Fatalf("%s: prior pair does not derive from the expected rotation key", connectorName)
				}
			}
		})
	}
}

// A rollback that reconciles a user already moved to the new key is
// configuration, not repair, even though the lifecycle has already renamed
// the staged key to the retiring file. The same rollback with a changed
// DefenseClaw hook, or a retiring key that is not the transaction key, is
// still a repair.
func TestGAP0638GAP0642CredentialRotationRollbackIsNotReportedAsRepair(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("the standalone worker runs as the account")
	}
	previousStandalone := enterprisehooks.StandaloneUnix()
	enterprisehooks.SetStandaloneUnix(true)
	t.Cleanup(func() { enterprisehooks.SetStandaloneUnix(previousStandalone) })
	committed, staged, other := strings.Repeat("1a", 32), strings.Repeat("2b", 32), strings.Repeat("3c", 32)
	for _, connectorName := range []string{"codex", "claudecode"} {
		for _, tc := range []struct {
			name        string
			afterRename bool
			wrongKey    bool
			changeHook  bool
			wantRepair  bool
		}{
			{name: "staged key renamed to retiring", afterRename: true},
			{name: "staged key not yet renamed"},
			{name: "retiring key is not the transaction key", afterRename: true, wrongKey: true, wantRepair: true},
			{name: "changed hook script during rollback", afterRename: true, changeHook: true, wantRepair: true},
		} {
			t.Run(connectorName+"/"+tc.name, func(t *testing.T) {
				home, opts := gap0638CredentialFixture(t, connectorName)
				identity := opts.HookCredentialIdentity
				// The user was already moved to the new (staged) key.
				moved := gap0638KeyPair(t, staged, connectorName, identity)
				opts.APIToken, opts.OTLPPathToken = moved.APIToken, moved.OTLPPathToken
				if _, err := enterprisehooks.Install(context.Background(), opts); err != nil {
					t.Fatalf("install on the new key: %v", err)
				}
				if tc.changeHook {
					conn, _ := connector.NewDefaultRegistry().Get(connectorName)
					owner, ok := conn.(interface {
						HookScriptNames(connector.SetupOpts) []string
					})
					if !ok || len(owner.HookScriptNames(connector.SetupOpts{})) == 0 {
						t.Fatalf("connector %s has no hook script", connectorName)
					}
					script := filepath.Join(home, ".defenseclaw", "hooks", owner.HookScriptNames(connector.SetupOpts{})[0])
					if err := os.WriteFile(script, []byte("changed hook\n"), 0o700); err != nil {
						t.Fatal(err)
					}
				}
				dataDir := gap0638RotationLayout(t, committed, staged, enterprisehooks.CredentialPhaseRollback, tc.afterRename)
				if tc.wrongKey {
					retiring, _ := connector.RetiringUserScopedTokenKeyPath(dataDir)
					if err := os.WriteFile(retiring, []byte(other+"\n"), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				prior := enterpriseHookPriorUserTokens(dataDir, connectorName, identity)
				// The rollback renders the committed key again.
				back := gap0638KeyPair(t, committed, connectorName, identity)
				opts.APIToken, opts.OTLPPathToken = back.APIToken, back.OTLPPathToken
				if got := gap0638Reconcile(t, opts, prior); got.Repaired != tc.wantRepair {
					t.Fatalf("%s %s: repaired=%t, want %t", connectorName, tc.name, got.Repaired, tc.wantRepair)
				}
			})
		}
	}
}
