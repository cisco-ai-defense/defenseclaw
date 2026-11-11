// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// An OpenCode the gateway finds on its own PATH can be a V1 that sits ahead of
// the V2 the account runs. That refusal and a removed agent both leave nothing
// to roll back, so a refresh stops only the OpenCode connector: the peers set
// up before and after it stay set up, the earlier OpenCode plugin and lock
// entry stay as they were, and the reason is named. Any other refusal of an
// active OpenCode still fails the refresh and rolls the peers back.
func TestSetupConnectorsIsolated_ActiveOpenCodeNotV2StopsOnlyOpenCode(t *testing.T) {
	for _, tc := range []struct {
		name          string
		discovery     string
		setupErr      error
		wantFailStart bool
		wantReason    []string
	}{
		{
			name:       "V1 first on the gateway PATH",
			discovery:  `{"agents":{"opencode":{"version":"1.18.34"}}}`,
			wantReason: []string{"not V2", "V2 is required", "defenseclaw-gateway restart", "defenseclaw setup remove opencode"},
		},
		{
			name:       "git build with no release version",
			discovery:  `{"agents":{"opencode":{"version":"0.0.0-main-202607010000"}}}`,
			wantReason: []string{"not V2", "defenseclaw setup remove opencode"},
		},
		{
			name:       "agent removed",
			discovery:  `{"agents":{"opencode":{"version":"","binary_path":"","installed":false}}}`,
			setupErr:   fmt.Errorf("OpenCode is gone: %w", connector.ErrSetupRefusedUnchanged),
			wantReason: []string{"the agent is not installed for this account", "defenseclaw setup remove opencode"},
		},
		{
			// V2 is present and Setup refused it for another reason: the
			// refresh still fails, as it did before this change.
			name:          "V2 present, Setup refused for another reason",
			discovery:     `{"agents":{"opencode":{"version":"2.1.4"}}}`,
			setupErr:      fmt.Errorf("plugin folder is not trusted: %w", connector.ErrSetupRefusedUnchanged),
			wantFailStart: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if runtime.GOOS == "windows" {
				t.Skip("the Windows OpenCode setup authority needs a protected install fixture")
			}
			s := multiBootSidecar(t)
			s.cfg.DataDir = testenv.PrivateTempDir(t)
			s.health = NewSidecarHealth()
			// The removed-agent proof reads the account home and PATH.
			testenv.SetHome(t, testenv.PrivateTempDir(t))
			t.Setenv("PATH", testenv.PrivateTempDir(t))
			configDir := testenv.PrivateTempDir(t)
			t.Setenv("OPENCODE_CONFIG_DIR", configDir)
			pluginPath := filepath.Join(configDir, "plugins", "defenseclaw.js")
			if err := os.MkdirAll(filepath.Dir(pluginPath), 0o700); err != nil {
				t.Fatal(err)
			}
			priorPlugin := []byte("// prior managed OpenCode plugin\n")
			if err := os.WriteFile(pluginPath, priorPlugin, 0o600); err != nil {
				t.Fatal(err)
			}
			priorOpts := prepareOpenCodeSetupAuthorityFixture(t, s.cfg.DataDir)
			priorLock := connector.NewHookContractLockEntry(priorOpts, connector.NewOpenCodeConnector(), "prior-test-build")
			if err := connector.SaveHookContractLockEntry(s.cfg.DataDir, priorLock); err != nil {
				t.Fatal(err)
			}
			if err := connector.SaveActiveConnectors(s.cfg.DataDir, []string{"opencode"}); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(s.cfg.DataDir, "agent_discovery.json"), []byte(tc.discovery), 0o600); err != nil {
				t.Fatal(err)
			}
			before := &bootStubConnector{stubConnector: stubConnector{name: "copilot"}}
			openCode := &bootStubConnector{stubConnector: stubConnector{name: "opencode"}, setupErr: tc.setupErr}
			after := &bootStubConnector{stubConnector: stubConnector{name: "codex"}}

			transaction, err := s.setupConnectorsIsolatedTransaction(context.Background(),
				[]connector.Connector{before, openCode, after}, "tok", "127.0.0.1:0", "127.0.0.1:0", "master", guardrail.NewRulePackCache())

			if plugin, readErr := os.ReadFile(pluginPath); readErr != nil || !bytes.Equal(plugin, priorPlugin) {
				t.Errorf("the earlier OpenCode plugin changed: %q (%v)", plugin, readErr)
			}
			if lock := connector.LoadHookContractLockEntry(s.cfg.DataDir, "opencode"); lock.ContractID != priorLock.ContractID || lock.RawAgentVersion != priorLock.RawAgentVersion {
				t.Errorf("the OpenCode lock entry changed: %+v, want %+v", lock, priorLock)
			}
			if active := connector.LoadActiveConnectors(s.cfg.DataDir); !reflect.DeepEqual(active, []string{"opencode"}) {
				t.Errorf("active connectors = %v, want opencode kept", active)
			}
			if tc.wantFailStart {
				if err == nil || !strings.Contains(err.Error(), "connector opencode refresh failed") {
					t.Fatalf("error = %v, want the refresh failure", err)
				}
				if before.teardownCalls != before.setupCalls || before.setupCalls == 0 {
					t.Errorf("peer setup=%d teardown=%d, want the peer registration rolled back", before.setupCalls, before.teardownCalls)
				}
				return
			}
			if err != nil {
				t.Fatalf("an OpenCode that cannot be refreshed stopped the start for every connector: %v", err)
			}
			if want := []string{"copilot", "codex"}; !reflect.DeepEqual(transaction.succeeded, want) {
				t.Fatalf("running connectors = %v, want %v", transaction.succeeded, want)
			}
			if before.teardownCalls != 0 || after.teardownCalls != 0 || openCode.teardownCalls != 0 {
				t.Errorf("teardowns = %d/%d/%d, want none", before.teardownCalls, openCode.teardownCalls, after.teardownCalls)
			}
			if errors.Is(tc.setupErr, connector.ErrSetupRefusedUnchanged) {
				if openCode.setupCalls != 1 {
					t.Errorf("OpenCode setup calls = %d, want 1", openCode.setupCalls)
				}
			} else if openCode.setupCalls != 0 {
				t.Errorf("OpenCode setup calls = %d, want the refusal before setup", openCode.setupCalls)
			}
			reason := transaction.agentSettingsRefused["opencode"]
			for _, want := range tc.wantReason {
				if !strings.Contains(reason, want) {
					t.Errorf("reason does not say %q: %s", want, reason)
				}
			}
			if skipped := s.health.connectorSkippedAtStartReason("opencode"); skipped != reason {
				t.Errorf("a retained OpenCode hook is not refused with the reason: %q", skipped)
			}
			if !reflect.DeepEqual(transaction.keptRegistrations, []string{"opencode"}) {
				t.Errorf("kept registrations = %v, want opencode", transaction.keptRegistrations)
			}
		})
	}
}
