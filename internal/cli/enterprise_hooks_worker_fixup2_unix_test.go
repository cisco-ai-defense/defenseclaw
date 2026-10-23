//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

func TestEnterpriseHookWorkerConfigReferenceLine(t *testing.T) {
	for _, tc := range []struct {
		name, config, dataDir string
		wantLine              int
	}{
		{"Codex bootstrap header", "# Created by DefenseClaw installer\n # DefenseClaw only owns [hooks], [otel]\n", "", 0},
		{"comment styles", "  # /home/sample-user/.defenseclaw/hooks/codex-hook.sh\n // x-defenseclaw-source\n", "", 0},
		{"hook path", "command = '/home/sample-user/.defenseclaw/hooks/codex-hook.sh'\n", "", 1},
		{"notify bridge", "notify = ['bash', '/home/sample-user/.defenseclaw/notify-bridge.sh']\n", "", 1},
		{"data dir name at quote", "value = '.defenseclaw'\n", "", 1},
		{"data dir name at end", "value = .defenseclaw\n", "", 1},
		{"data dir name at backslash", "value = '.defenseclaw\\hooks'\n", "", 1},
		{"managed marker", "hook = 'defenseclaw-managed-hook v8'\n", "", 1},
		{"source header", "x-defenseclaw-source = 'codex'\n", "", 1},
		{"client header", "x-defenseclaw-client = 'codex-otel/1.0'\n", "", 1},
		{"native launcher", "command = 'defenseclaw-hook hook codex'\n", "", 1},
		{"plugin file", "plugin = '/home/sample-user/.config/opencode/plugins/defenseclaw.js'\n", "", 1},
		{"project uppercase", "[projects.\"/srv/work/DefenseClaw\"]\ntrust_level = 'trusted'\n", "", 0},
		{"project lowercase", "[projects.\"/home/sample-user/code/defenseclaw\"]\ntrust_level = 'trusted'\n", "", 0},
		{"dotted project directory", "[projects.\"/srv/work/project.defenseclaw/hooks\"]\ntrust_level = 'trusted'\n", "", 0},
		{"dotted filename", "value = 'www.defenseclaw'\n", "", 0},
		{"similar dot directory", "value = '.defenseclaw-backup'\n", "", 0},
		{"custom data dir", "command = '/home/sample-user/custom-hooks/hooks/agent.sh'\n", "/home/sample-user/custom-hooks", 1},
		{"other data dir", "command = '/home/sample-user/custom-hooks/hooks/agent.sh'\n", "/home/sample-user/another-hooks", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			line, reason := enterpriseHookWorkerConfigReferenceLine([]byte(tc.config), tc.dataDir)
			if line != tc.wantLine || (line != 0 && reason == "") {
				t.Fatalf("match = %d, %q; want line %d", line, reason, tc.wantLine)
			}
		})
	}
}

func TestEnterpriseHookWorkerUnverifiedReportValidation(t *testing.T) {
	valid := enterpriseHookWorkerTargetResult{Index: 0, OK: true, Unverified: "load managed backup /home/sample-user/.defenseclaw/connector_backups/codex/notes.json: invalid"}
	if err := validateEnterpriseHookWorkerRemoveReport(valid); err != nil {
		t.Fatalf("valid unverified report: %v", err)
	}
	remove := enterpriseHookWorkerTarget{Mode: enterpriseHookWorkerModeRemove}
	if err := validateEnterpriseHookWorkerResult(remove, valid); err != nil {
		t.Fatalf("valid unverified result: %v", err)
	}
	for _, tc := range []struct {
		name   string
		result enterpriseHookWorkerTargetResult
	}{
		{"report and reason", enterpriseHookWorkerTargetResult{PathsReported: true, Unverified: "receipt unreadable"}},
		{"oversized", enterpriseHookWorkerTargetResult{Unverified: strings.Repeat("x", enterpriseHookWorkerRemainingMax+1)}},
		{"invalid utf8", enterpriseHookWorkerTargetResult{Unverified: string([]byte{0xff})}},
		{"control", enterpriseHookWorkerTargetResult{Unverified: "receipt\nname"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateEnterpriseHookWorkerRemoveReport(tc.result); err == nil {
				t.Fatal("invalid unverified report accepted")
			}
		})
	}
	for _, mode := range []string{enterpriseHookWorkerModeInstall, enterpriseHookWorkerModeVerify, enterpriseHookWorkerModePurge} {
		if err := validateEnterpriseHookWorkerResult(enterpriseHookWorkerTarget{Mode: mode}, valid); err == nil {
			t.Fatalf("%s accepted a Remove-only reason", mode)
		}
	}
}

func TestEnterpriseHookWorkerCollectionFailureStillRemoves(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("the per-user worker requires a non-root test account")
	}
	for _, tc := range []struct {
		name, path, logical string
		count               int
	}{
		{name: "too many paths", count: enterpriseHookWorkerRemovePathsMax},
		{name: "oversized path", path: "/" + strings.Repeat("a", enterpriseHookWorkerRemovePathMax+1), logical: "oversized"},
		{name: "relative path", path: "relative/config", logical: "relative"},
		{name: "unclean path", path: "/tmp/nested/../config", logical: "unclean"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			dataDir := filepath.Join(home, ".defenseclaw")
			receipts := filepath.Join(dataDir, "connector_backups", "opencode")
			if err := os.MkdirAll(receipts, 0o700); err != nil {
				t.Fatal(err)
			}
			write := func(logical, target string) {
				t.Helper()
				data, err := json.Marshal(map[string]interface{}{"version": 1, "connector": "opencode", "logical_name": logical, "path": target})
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(receipts, logical+".json"), data, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if tc.count != 0 {
				for i := 0; i < tc.count; i++ {
					write("item"+strconv.Itoa(i), filepath.Join(home, "item", strconv.Itoa(i)))
				}
			} else {
				write(tc.logical, tc.path)
			}
			previous := enterpriseHookWorkerRemover
			t.Cleanup(func() { enterpriseHookWorkerRemover = previous })
			calls := 0
			enterpriseHookWorkerRemover = func(context.Context, enterprisehooks.InstallOptions) error { calls++; return nil }
			opts := enterprisehooks.InstallOptions{ConnectorName: "opencode", UserHome: home, OwnerUID: os.Getuid(), OwnerGID: os.Getgid(), DataDir: dataDir, Registry: connector.NewDefaultRegistry()}
			request := enterpriseHookWorkerRequest{Home: home, UID: os.Getuid(), GID: os.Getgid(), Targets: []enterpriseHookWorkerTarget{{Index: 0, Mode: enterpriseHookWorkerModeRemove, Options: enterpriseHookWorkerOptionsFrom(opts)}}}
			result := runEnterpriseHookWorkerApply(context.Background(), request).Targets[0]
			if calls != 1 || !result.OK || result.PathsReported || result.Unverified == "" || len(result.CleanedPaths) != 0 || result.Remaining != "" {
				t.Fatalf("collection failure blocked remover or claimed proof: calls=%d result=%+v", calls, result)
			}
			if err := validateEnterpriseHookWorkerResult(request.Targets[0], result); err != nil {
				t.Fatalf("worker emitted invalid unverified reason: %v", err)
			}
		})
	}
}

func TestEnterpriseHookWorkerSetupErrorKeepsRemoverError(t *testing.T) {
	previous := enterpriseHookWorkerRemover
	t.Cleanup(func() { enterpriseHookWorkerRemover = previous })
	calls := 0
	enterpriseHookWorkerRemover = func(context.Context, enterprisehooks.InstallOptions) error {
		calls++
		return errors.New("enterprise hooks: unknown connector \"missing\"")
	}
	request := enterpriseHookWorkerRequest{Home: "/home/sample-user", Targets: []enterpriseHookWorkerTarget{{
		Index: 0, Mode: enterpriseHookWorkerModeRemove,
		Options: enterpriseHookWorkerOptions{ConnectorName: "missing", UserHome: "/home/sample-user"},
	}}}
	result := runEnterpriseHookWorkerApply(context.Background(), request).Targets[0]
	if calls != 1 || result.OK || result.Error != "enterprise hooks: unknown connector \"missing\"" {
		t.Fatalf("setup error changed remover result: calls=%d result=%+v", calls, result)
	}
}

func TestEnterpriseHookWorkerConfigScanKeepsReadLimits(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, "config.toml")
	outside := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(outside, []byte("hook = '/tmp/.defenseclaw/hooks/owned.sh'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := enterpriseHookWorkerRemainingConfigReference(home, filepath.Join(home, ".defenseclaw"), []string{outside}); got != "" {
		t.Fatalf("off-home path was read: %s", got)
	}
	if err := os.Symlink(outside, path); err != nil {
		t.Fatal(err)
	}
	// A link out of the home is read as the account (never changed), so
	// the entry in the file it names is reported (rel-1-0-3 GAP-0206).
	if got := enterpriseHookWorkerRemainingConfigReference(home, filepath.Join(home, ".defenseclaw"), []string{path}); !strings.Contains(got, path+":1: DefenseClaw data-dir path remains") {
		t.Fatalf("a symlink out of the home was treated as clean: %s", got)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(4<<20 + 1); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if got := enterpriseHookWorkerRemainingConfigReference(home, filepath.Join(home, ".defenseclaw"), []string{path}); !strings.Contains(got, "read limit") {
		t.Fatalf("oversized file was treated as clean: %s", got)
	}
}

func TestEnterpriseHookWorkerUnverifiedJSONIsRemoveOnly(t *testing.T) {
	previousInstaller, previousVerifier, previousRemover := enterpriseHookWorkerInstaller, enterpriseHookWorkerVerifier, enterpriseHookWorkerRemover
	t.Cleanup(func() {
		enterpriseHookWorkerInstaller, enterpriseHookWorkerVerifier, enterpriseHookWorkerRemover = previousInstaller, previousVerifier, previousRemover
	})
	home := t.TempDir()
	result := enterprisehooks.InstallResult{Connector: "opencode", UserHome: home}
	enterpriseHookWorkerInstaller = func(context.Context, enterprisehooks.InstallOptions) (enterprisehooks.InstallResult, error) {
		return result, nil
	}
	enterpriseHookWorkerVerifier = enterpriseHookWorkerInstaller
	enterpriseHookWorkerRemover = func(context.Context, enterprisehooks.InstallOptions) error { return nil }
	request := enterpriseHookWorkerRequest{Home: home, Targets: []enterpriseHookWorkerTarget{{Index: 0,
		Options: enterpriseHookWorkerOptions{ConnectorName: "opencode", UserHome: home},
	}}}
	for _, mode := range []string{enterpriseHookWorkerModeInstall, enterpriseHookWorkerModeVerify} {
		request.Targets[0].Mode = mode
		got, err := json.Marshal(runEnterpriseHookWorkerApply(context.Background(), request).Targets[0])
		if err != nil {
			t.Fatal(err)
		}
		want, err := json.Marshal(enterpriseHookWorkerTargetResult{Index: 0, OK: true, Result: &result})
		if err != nil || string(got) != string(want) || strings.Contains(string(got), "unverified") {
			t.Fatalf("%s JSON changed: %s, want %s", mode, got, want)
		}
	}
	request.Targets[0].Mode = enterpriseHookWorkerModeRemove
	got, err := json.Marshal(runEnterpriseHookWorkerApply(context.Background(), request).Targets[0])
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(got), "unverified") {
		t.Fatalf("successful Remove emitted an unverified field: %s", got)
	}
}

func TestEnterpriseHookWorkerMatcherCoversInstallAndRemovalByConnector(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("the per-user installer requires a non-root test account")
	}
	registry := connector.NewDefaultRegistry()
	// Proxy connectors are setup-only and Install refuses them before any
	// per-user hook config is written.
	setupOnly := map[string]bool{"openclaw": true, "zeptoclaw": true}
	versions := map[string]string{
		"amp": "0.0.1785334225", "codex": "codex-cli 0.142.0",
		"claudecode": "2.1.187 (Claude Code)", "opencode": "1.18.33",
		"kiro":        "kiro-cli 2.24.1",
		"antigravity": "1.2.11",
		"hermes":      "0.21.3", "cursor": "cursor 3.19.13",
		"devin": "3000.4.25", "copilot": "GitHub Copilot CLI 1.0.76",
	}
	seed := map[string]struct{ path, data string }{
		"hermes":      {".hermes/config.yaml", "{}\n"},
		"antigravity": {".gemini/config/hooks.json", "{}\n"},
		"devin":       {".config/devin/config.json", "{}\n"},
	}
	for _, name := range registry.Names() {
		t.Run(name, func(t *testing.T) {
			if setupOnly[name] {
				t.Skip("proxy connector: per-user Install is setup-only")
			}
			home := t.TempDir()
			if err := os.Chmod(home, 0o700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("HOME", home)
			t.Setenv("XDG_CONFIG_HOME", "")
			t.Setenv("OPENCODE_CONFIG_DIR", "")
			t.Setenv("CODEX_HOME", "")
			if name == "kiro" || name == "copilot" {
				enterprisehooks.SetStandaloneUnix(true)
				t.Cleanup(func() { enterprisehooks.SetStandaloneUnix(false) })
			}
			if name == "kiro" {
				if err := os.MkdirAll(filepath.Join(home, ".kiro", "hooks"), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if name == "copilot" {
				if err := os.MkdirAll(filepath.Join(home, ".copilot", "hooks"), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if fixture, ok := seed[name]; ok {
				path := filepath.Join(home, fixture.path)
				if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(fixture.data), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			opts := enterprisehooks.InstallOptions{
				ConnectorName: name, UserHome: home, OwnerUID: os.Getuid(), OwnerGID: os.Getgid(),
				APIAddr: "127.0.0.1:18970", ProxyAddr: "127.0.0.1:4000",
				APIToken: strings.Repeat("a", 64), OTLPPathToken: strings.Repeat("b", 64),
				GuardrailMode: "action", HookFailMode: "closed", AgentVersion: versions[name],
				Registry: registry,
			}
			if _, err := enterprisehooks.Install(context.Background(), opts); err != nil {
				t.Fatalf("Install(%s) in a fresh user home: %v", name, err)
			}
			conn, ok := registry.Get(name)
			if !ok {
				t.Fatalf("connector %s left the registry", name)
			}
			setupOpts := connector.SetupOpts{DataDir: filepath.Join(home, ".defenseclaw"),
				ManagedEnterprise: true, AgentVersion: opts.AgentVersion}
			var paths []string
			if err := connector.WithUserHomeDir(home, func() error {
				paths = connector.CleanupConfigPathsForConnector(conn, setupOpts)
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if len(paths) == 0 {
				t.Fatal("connector exposed no cleanup config path")
			}
			matched := false
			for _, path := range paths {
				data, err := os.ReadFile(path)
				if errors.Is(err, os.ErrNotExist) {
					continue
				}
				if err != nil {
					t.Fatal(err)
				}
				line, _ := enterpriseHookWorkerConfigReferenceLine(data, "")
				matched = matched || line != 0
			}
			if !matched {
				t.Fatalf("matcher missed installed %s entries in %v", name, paths)
			}
			if err := enterprisehooks.RemoveUserHooks(context.Background(), opts); err != nil {
				t.Fatalf("RemoveUserHooks(%s): %v", name, err)
			}
			if remaining := enterpriseHookWorkerRemainingConfigReference(home, setupOpts.DataDir, paths); remaining != "" {
				t.Fatalf("matcher kept removed %s entries: %s", name, remaining)
			}
		})
	}
}

// A dotfile manager links the agent config to a file in the same home. The
// check reads that file: clean, the row ends; with an entry left, it stays
// (GAP-0642).
func TestEnterpriseHookWorkerConfigScanFollowsLinksInsideTheHome(t *testing.T) {
	home := t.TempDir()
	dataDir := filepath.Join(home, ".defenseclaw")
	dotfile := filepath.Join(home, "dotfiles", "codex.toml")
	path := filepath.Join(home, ".codex", "config.toml")
	for _, dir := range []string{filepath.Dir(dotfile), filepath.Dir(path)} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(dotfile, []byte("model = 'sample'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(dotfile, path); err != nil {
		t.Fatal(err)
	}
	if got := enterpriseHookWorkerRemainingConfigReference(home, dataDir, []string{path}); got != "" {
		t.Fatalf("a clean linked config stayed unverified: %s", got)
	}
	if err := os.WriteFile(dotfile, []byte("model = 'sample'\nnotify = ['"+filepath.Join(dataDir, "hooks", "codex-hook.sh")+"']\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := enterpriseHookWorkerRemainingConfigReference(home, dataDir, []string{path}); !strings.Contains(got, path+":2: DefenseClaw data-dir path remains") {
		t.Fatalf("an entry in the linked config was not reported: %q", got)
	}
	if err := os.Remove(dotfile); err != nil {
		t.Fatal(err)
	}
	if got := enterpriseHookWorkerRemainingConfigReference(home, dataDir, []string{path}); !strings.Contains(got, "cannot be resolved") {
		t.Fatalf("a dangling link was treated as clean: %q", got)
	}
	// A link out of the home is read as the account, never changed: a
	// clean file passes and an entry in it is reported (rel-1-0-3 GAP-0206).
	outside := filepath.Join(t.TempDir(), "codex.toml")
	if err := os.WriteFile(outside, []byte("model = 'sample'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, path); err != nil {
		t.Fatal(err)
	}
	if got := enterpriseHookWorkerRemainingConfigReference(home, dataDir, []string{path}); got != "" {
		t.Fatalf("a clean outside-home linked config stayed unverified: %s", got)
	}
	if err := os.WriteFile(outside, []byte("notify = ['"+filepath.Join(dataDir, "hooks", "codex-hook.sh")+"']\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := enterpriseHookWorkerRemainingConfigReference(home, dataDir, []string{path}); !strings.Contains(got, path+":1: DefenseClaw data-dir path remains") {
		t.Fatalf("an entry in the outside-home linked config was not reported: %q", got)
	}
}
