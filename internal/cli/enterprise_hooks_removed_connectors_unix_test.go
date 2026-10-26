//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// until 1.1 (GAP-1845): a managed Linux/macOS account a 1.0.4 standalone
// guardian set up for OpenHands and OmniGent. The guardian's next apply job
// for the account (the package upgrade, the verify timer, uninstall) removes
// what DefenseClaw wrote for them and keeps the account's own entries; the
// job never fails on it, and the Secure Client guardian leaves it alone.
func TestManagedUnixGuardianJobRemovesWhatDefenseClawWroteForRemovedConnectors(t *testing.T) {
	for _, standalone := range []bool{true, false} {
		t.Run("standalone="+strconv.FormatBool(standalone), func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			t.Setenv("OMNIGENT_CONFIG", "")
			t.Setenv("OMNIGENT_CONFIG_HOME", "")
			dataDir := filepath.Join(home, ".defenseclaw")
			script := filepath.Join(dataDir, "hooks", "openhands-hook.sh")
			module := filepath.Join(dataDir, "hooks", "defenseclaw_omnigent_policy.py")
			hooksJSON := filepath.Join(home, ".openhands", "hooks.json")
			omniConfig := filepath.Join(home, ".omnigent", "config.yaml")
			files := map[string]string{
				script: "#!/bin/sh -p\n# defenseclaw-managed-hook v0 (disabled tombstone)\nexit 2\n",
				module: "# defenseclaw-managed-policy v0 (disabled tombstone)\nraise SystemExit(2)\n",
				hooksJSON: `{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":` + strconv.Quote(script) +
					`},{"type":"command","command":"/opt/mine/hook"}]}]}`,
				omniConfig: "policy_modules:\n  - operator_own_policy\n  - defenseclaw_omnigent_policy\nmodel: m\n",
			}
			for path, body := range files {
				if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			previousVerifier, previousLog := enterpriseHookWorkerVerifier, enterpriseHookWorkerRemovedLog
			t.Cleanup(func() { enterpriseHookWorkerVerifier, enterpriseHookWorkerRemovedLog = previousVerifier, previousLog })
			enterpriseHookWorkerVerifier = func(_ context.Context, opts enterprisehooks.InstallOptions) (enterprisehooks.InstallResult, error) {
				return enterprisehooks.InstallResult{Connector: opts.ConnectorName, UserHome: opts.UserHome}, nil
			}
			var log bytes.Buffer
			enterpriseHookWorkerRemovedLog = &log
			request := enterpriseHookWorkerRequest{
				Home: home, UID: os.Getuid(), GID: os.Getgid(), Standalone: standalone,
				Targets: []enterpriseHookWorkerTarget{{Index: 0, Mode: enterpriseHookWorkerModeVerify, Options: enterpriseHookWorkerOptions{
					ConnectorName: "codex", UserHome: home, OwnerUID: os.Getuid(), OwnerGID: os.Getgid(), DataDir: dataDir,
				}}},
			}
			results := runEnterpriseHookWorkerApply(context.Background(), request).Targets
			if len(results) != 1 || !results[0].OK {
				t.Fatalf("the job failed: %+v", results)
			}
			hooks, _ := os.ReadFile(hooksJSON)
			omni, _ := os.ReadFile(omniConfig)
			_, scriptErr := os.Lstat(script)
			_, moduleErr := os.Lstat(module)
			if !standalone {
				if !strings.Contains(string(hooks), "openhands-hook.sh") || scriptErr != nil || log.Len() != 0 {
					t.Fatalf("the Secure Client guardian changed the account: hooks.json=%s log=%q", hooks, log.String())
				}
				return
			}
			if strings.Contains(string(hooks), "openhands-hook.sh") || !strings.Contains(string(hooks), "/opt/mine/hook") {
				t.Errorf("hooks.json after the job:\n%s", hooks)
			}
			if strings.Contains(string(omni), "defenseclaw_omnigent_policy") || !strings.Contains(string(omni), "operator_own_policy") {
				t.Errorf("config.yaml after the job:\n%s", omni)
			}
			if scriptErr == nil || moduleErr == nil {
				t.Errorf("a deny stub is still there: script=%v module=%v", scriptErr, moduleErr)
			}
			if got := strings.Count(log.String(), connector.RemovedConnectorNotice); got != 1 {
				t.Errorf("the notice was logged %d times:\n%s", got, log.String())
			}
		})
	}
}
