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
		// Windows: the OpenCode version is the protected selected-executable
		// evidence's, never agent_discovery.json or the gateway PATH. That
		// evidence is only ever published for a version a hook contract
		// covers, so a V1 or a git build can never be the version the gateway
		// reads: windowsUnreadableVersion is the version the Unix row's agent
		// reports, and the Windows row asserts what the gateway does with no
		// valid version evidence instead (see
		// assertWindowsOpenCodeWithoutVersionEvidence). A removed OpenCode
		// cannot be proven removed (only an Amp package path can), so it fails
		// the refresh like any other refusal (windowsRemovedFails).
		windowsUnreadableVersion string
		windowsRemovedFails      bool
	}{
		{
			name:                     "V1 first on the gateway PATH",
			discovery:                `{"agents":{"opencode":{"version":"1.18.34"}}}`,
			windowsUnreadableVersion: "1.18.34",
			wantReason:               []string{"not V2", "V2 is required", "defenseclaw-gateway restart", "defenseclaw setup remove opencode"},
		},
		{
			name:                     "git build with no release version",
			discovery:                `{"agents":{"opencode":{"version":"0.0.0-main-202607010000"}}}`,
			windowsUnreadableVersion: "0.0.0-main-202607010000",
			wantReason:               []string{"not V2", "defenseclaw setup remove opencode"},
		},
		{
			name:                "agent removed",
			discovery:           `{"agents":{"opencode":{"version":"","binary_path":"","installed":false}}}`,
			setupErr:            fmt.Errorf("OpenCode is gone: %w", connector.ErrSetupRefusedUnchanged),
			windowsRemovedFails: true,
			wantReason:          []string{"the agent is not installed for this account", "defenseclaw setup remove opencode"},
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
			if runtime.GOOS == "windows" && tc.windowsUnreadableVersion != "" {
				assertWindowsOpenCodeWithoutVersionEvidence(t, s, tc.windowsUnreadableVersion, tc.discovery, pluginPath, priorPlugin)
				return
			}
			priorOpts := prepareOpenCodeSetupAuthorityFixtureForVersion(t, s.cfg.DataDir, "2.1.4")
			wantFailStart := tc.wantFailStart || (runtime.GOOS == "windows" && tc.windowsRemovedFails)
			priorLock := connector.NewHookContractLockEntry(priorOpts, connector.NewOpenCodeConnector(), "prior-test-build")
			if err := connector.SaveHookContractLockEntry(s.cfg.DataDir, priorLock); err != nil {
				t.Fatal(err)
			}
			if err := connector.SaveActiveConnectors(s.cfg.DataDir, []string{"opencode"}); err != nil {
				t.Fatal(err)
			}
			if runtime.GOOS == "windows" && tc.windowsRemovedFails {
				// The agent is removed after its evidence was locked.
				if err := os.Remove(priorOpts.AgentExecutable); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(filepath.Join(s.cfg.DataDir, "agent_discovery.json"), []byte(tc.discovery), 0o600); err != nil {
				t.Fatal(err)
			}
			before := &bootStubConnector{stubConnector: stubConnector{name: "copilot"}}
			openCode := &bootStubConnector{stubConnector: stubConnector{name: "opencode"}, setupErr: tc.setupErr}
			after := &bootStubConnector{stubConnector: stubConnector{name: "codex"}}

			transaction, err := s.setupConnectorsIsolatedTransaction(context.Background(),
				[]connector.Connector{before, openCode, after}, "tok", "127.0.0.1:0", "127.0.0.1:0", guardrail.NewRulePackCache())

			if plugin, readErr := os.ReadFile(pluginPath); readErr != nil || !bytes.Equal(plugin, priorPlugin) {
				t.Errorf("the earlier OpenCode plugin changed: %q (%v)", plugin, readErr)
			}
			if lock := connector.LoadHookContractLockEntry(s.cfg.DataDir, "opencode"); lock.ContractID != priorLock.ContractID || lock.RawAgentVersion != priorLock.RawAgentVersion {
				t.Errorf("the OpenCode lock entry changed: %+v, want %+v", lock, priorLock)
			}
			if active := connector.LoadActiveConnectors(s.cfg.DataDir); !reflect.DeepEqual(active, []string{"opencode"}) {
				t.Errorf("active connectors = %v, want opencode kept", active)
			}
			if wantFailStart {
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

// assertWindowsOpenCodeWithoutVersionEvidence is the Windows twin of the V1 and
// git-build rows. The rule it pins: a Windows gateway reads an OpenCode version
// only from the protected setup-selected executable evidence
// (connector.LoadCachedAgentVersion), never from agent_discovery.json or its own
// PATH, and that evidence is published only for a version a hook contract covers
// (opencode_admission_windows.go). A V1 or a git build therefore never becomes a
// version the gateway can read, and RequireOpenCodeV2 never sees it: the
// OpenCode is unversioned. Unversioned keeps the existing admission policy
// (RequireOpenCodeV2: "Unreadable versions retain the existing unversioned
// admission policy; they never select a V1 implementation"): observe mode runs
// the refresh, action mode refuses the refresh like any other admission failure
// of an active connector (the unversioned refusal is not the isolated V2 one).
func assertWindowsOpenCodeWithoutVersionEvidence(t *testing.T, s *Sidecar, rawVersion, discovery, pluginPath string, priorPlugin []byte) {
	t.Helper()
	opts := prepareOpenCodeSetupAuthorityFixtureForVersion(t, s.cfg.DataDir, rawVersion)
	// The setup authority refuses to publish a contract for this version ...
	lock := connector.NewHookContractLockEntry(opts, connector.NewOpenCodeConnector(), "prior-test-build")
	err := connector.SaveHookContractLockEntry(s.cfg.DataDir, lock)
	if err == nil || !strings.Contains(err.Error(), "setup-selected executable evidence") {
		t.Fatalf("publishing a contract for OpenCode %s = %v, want the missing valid setup-selected executable evidence refusal", rawVersion, err)
	}
	// ... and the receipt of the selection is not a version the gateway reads.
	if got := connector.LoadCachedAgentVersion(s.cfg.DataDir, "opencode"); got != "" {
		t.Fatalf("the gateway reads OpenCode version %q from evidence that no contract covers, want none", got)
	}
	if err := connector.SaveActiveConnectors(s.cfg.DataDir, []string{"opencode"}); err != nil {
		t.Fatal(err)
	}
	// agent_discovery.json (the Unix source of the version) is ignored.
	if err := os.WriteFile(filepath.Join(s.cfg.DataDir, "agent_discovery.json"), []byte(discovery), 0o600); err != nil {
		t.Fatal(err)
	}
	refresh := func() (*bootStubConnector, *bootStubConnector, *bootStubConnector, multiConnectorSetupTransaction, error) {
		before := &bootStubConnector{stubConnector: stubConnector{name: "copilot"}}
		openCode := &bootStubConnector{stubConnector: stubConnector{name: "opencode"}}
		after := &bootStubConnector{stubConnector: stubConnector{name: "codex"}}
		transaction, err := s.setupConnectorsIsolatedTransaction(context.Background(),
			[]connector.Connector{before, openCode, after}, "tok", "127.0.0.1:0", "127.0.0.1:0", guardrail.NewRulePackCache())
		return before, openCode, after, transaction, err
	}
	checkUntouched := func() {
		t.Helper()
		if plugin, readErr := os.ReadFile(pluginPath); readErr != nil || !bytes.Equal(plugin, priorPlugin) {
			t.Errorf("the earlier OpenCode plugin changed: %q (%v)", plugin, readErr)
		}
		if active := connector.LoadActiveConnectors(s.cfg.DataDir); !reflect.DeepEqual(active, []string{"opencode"}) {
			t.Errorf("active connectors = %v, want opencode kept", active)
		}
	}

	// Observe mode: the unversioned OpenCode passes admission like any other
	// unversioned agent (Setup runs for it; the version in discovery decides
	// nothing). The stub connector writes no plugin, so the refresh then ends
	// at the registration verification: that is not the admission refusal and
	// not the isolated "not V2" stop.
	_, openCode, _, transaction, err := refresh()
	if openCode.setupCalls != 1 {
		t.Errorf("observe mode: OpenCode setup calls = %d, want 1 (admitted)", openCode.setupCalls)
	}
	if err != nil && (errors.Is(err, ErrHookContractAdmission) || strings.Contains(err.Error(), "not V2") ||
		!strings.Contains(err.Error(), "registration verification failed")) {
		t.Errorf("observe mode: error = %v, want admission passed and only the stub's registration verification failing", err)
	}
	if reason := transaction.agentSettingsRefused["opencode"]; reason != "" {
		t.Errorf("observe mode: OpenCode was isolated as not V2 (%q); Windows reads no version for it", reason)
	}
	checkUntouched()

	// Action mode: an unversioned agent is not verified against a hook
	// contract, so the refresh of an active OpenCode fails and rolls the peer
	// registration back; it is not the isolated "not V2" stop.
	s.cfg.Guardrail.Mode = "action"
	before, _, _, _, err := refresh()
	if err == nil || !strings.Contains(err.Error(), "connector opencode refresh failed") ||
		!errors.Is(err, ErrHookContractAdmission) {
		t.Fatalf("action mode: error = %v, want the unversioned hook contract admission refusal of the OpenCode refresh", err)
	}
	if strings.Contains(err.Error(), "not V2") {
		t.Errorf("action mode: the refusal names a V1 the Windows gateway cannot read: %v", err)
	}
	if before.teardownCalls != before.setupCalls {
		t.Errorf("action mode: peer setup=%d teardown=%d, want any peer registration rolled back", before.setupCalls, before.teardownCalls)
	}
	checkUntouched()
}
