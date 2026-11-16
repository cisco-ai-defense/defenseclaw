//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// A Codex config that is a symlink out of the home is left alone by the
// per-user removal: the file it names keeps its bytes (it held DefenseClaw's
// hooks, so a teardown would have deleted it), the link stays, the removal
// fails with the remedy, and a purge in the same job keeps the state. Also
// when the outside file and its folder are read-only, as a root-owned
// target is to the account. The connector writes refuse the same link on
// their own, without the worker's check (rel-1-0-3 GAP-0206).
func TestEnterpriseHookWorkerRemoveLeavesAnOutsideHomeConfigLinkAlone(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("the per-user worker requires a non-root test account")
	}
	previousStop := enterpriseHookWorkerStopPerUser
	previousPath := connector.CodexConfigPathOverride
	connector.CodexConfigPathOverride = ""
	t.Cleanup(func() {
		enterpriseHookWorkerStopPerUser = previousStop
		connector.CodexConfigPathOverride = previousPath
	})
	enterpriseHookWorkerStopPerUser = func(enterprisehooks.InstallOptions) (bool, error) { return false, nil }
	t.Setenv("CODEX_HOME", "")

	for _, readOnly := range []bool{false, true} {
		name := "account-owned target"
		if readOnly {
			name = "read-only target"
		}
		t.Run(name, func(t *testing.T) {
			home := t.TempDir()
			if err := os.Chmod(home, 0o700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("HOME", home)
			config := filepath.Join(home, ".codex", "config.toml")
			if err := os.MkdirAll(filepath.Dir(config), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(config, []byte("model = \"gpt-5\"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			opts := enterprisehooks.InstallOptions{
				ConnectorName: "codex", UserHome: home, OwnerUID: os.Getuid(), OwnerGID: os.Getgid(),
				APIAddr: "127.0.0.1:18970", ProxyAddr: "127.0.0.1:4000",
				APIToken: strings.Repeat("a", 64), OTLPPathToken: strings.Repeat("b", 64),
				GuardrailMode: "action", HookFailMode: "closed", AgentVersion: "codex-cli 0.142.0",
				Registry: connector.NewDefaultRegistry(),
			}
			if _, err := enterprisehooks.Install(context.Background(), opts); err != nil {
				t.Fatalf("install Codex: %v", err)
			}
			installed, err := os.ReadFile(config)
			if err != nil || !bytes.Contains(installed, []byte("codex-hook.sh")) {
				t.Fatalf("installed Codex config has no DefenseClaw hook: %v", err)
			}
			// The account keeps its config outside the home and links it.
			outsideDir := t.TempDir()
			outside := filepath.Join(outsideDir, "config.toml")
			if err := os.WriteFile(outside, installed, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(config); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outside, config); err != nil {
				t.Fatal(err)
			}
			if readOnly {
				if err := os.Chmod(outside, 0o400); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(outsideDir, 0o500); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Chmod(outsideDir, 0o700) })
			}
			unchanged := func(t *testing.T, what string) {
				t.Helper()
				if data, err := os.ReadFile(outside); err != nil || !bytes.Equal(data, installed) {
					t.Fatalf("%s changed the file outside the home: %v", what, err)
				}
				if target, err := os.Readlink(config); err != nil || target != outside {
					t.Fatalf("%s changed the config link: %q, %v", what, target, err)
				}
			}

			purge := enterpriseHookWorkerTarget{Index: 1, Mode: enterpriseHookWorkerModePurge, Options: enterpriseHookWorkerOptions{
				UserHome: home, OwnerUID: os.Getuid(), OwnerGID: os.Getgid(), DataDir: filepath.Join(home, ".defenseclaw"),
			}}
			request := enterpriseHookWorkerRequest{Home: home, UID: os.Getuid(), GID: os.Getgid(), Targets: []enterpriseHookWorkerTarget{
				{Index: 0, Mode: enterpriseHookWorkerModeRemove, Options: enterpriseHookWorkerOptionsFrom(opts)}, purge,
			}}
			results := runEnterpriseHookWorkerApply(context.Background(), request).Targets
			if len(results) != 2 {
				t.Fatalf("worker answered %d targets: %+v", len(results), results)
			}
			if results[0].OK || !strings.Contains(results[0].Error, "leads outside the home, to "+outside+", and that file still holds DefenseClaw's") ||
				!strings.Contains(results[0].Error, "DefenseClaw changed neither the link nor that file") ||
				!strings.HasSuffix(results[0].Error, "then rerun") {
				t.Fatalf("remove of an outside-home link = %+v", results[0])
			}
			if results[1].OK || !strings.Contains(results[1].Error, "kept the per-user state") {
				t.Fatalf("purge ran after the refused removal: %+v", results[1])
			}
			if _, err := os.Stat(filepath.Join(home, ".defenseclaw", "connector_backups")); err != nil {
				t.Fatalf("the per-user state went: %v", err)
			}
			unchanged(t, "the worker")

			// Without the worker's check, the teardown's own writes refuse.
			err = enterprisehooks.RemoveUserHooks(context.Background(), opts)
			if err == nil || !strings.Contains(err.Error(), "leads outside the home") {
				t.Fatalf("teardown through an outside-home link = %v", err)
			}
			unchanged(t, "the teardown")

			// The account follows the remedy and removes DefenseClaw's
			// entries from the outside file: the removal then goes on and
			// leaves that file and the link as they are.
			if readOnly {
				if err := os.Chmod(outsideDir, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(outside, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			cleaned := []byte("model = \"gpt-5\"\n")
			if err := os.WriteFile(outside, cleaned, 0o600); err != nil {
				t.Fatal(err)
			}
			installed = cleaned
			results = runEnterpriseHookWorkerApply(context.Background(), request).Targets
			if len(results) != 2 || !results[0].OK || !results[0].PathsReported || results[0].Remaining != "" || !results[1].OK {
				t.Fatalf("removal after the outside file was cleaned = %+v", results)
			}
			unchanged(t, "the removal after the account cleaned the file")
		})
	}
}
