// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// TestGAP0114MachinePolicyCallerGetsItsVerifiedAgentVersion: on managed
// Linux and macOS, Claude Code and Codex are machine-policy connectors with
// no per-user guardian row, so the 047d641da6 ledger lookup had nothing to
// read and every hook row said hook_compatibility_status=unversioned ("agent
// version not probed"). The enumerator publishes each account's verified
// version beside the ledger (agent-versions.json); the caller's profile now
// carries that version, judged against the contract the one machine-wide
// render speaks (the connector's unversioned contract), never a contract the
// render does not speak. A caller with no published version, and an
// unreadable record, resolve as before.
func TestGAP0114MachinePolicyCallerGetsItsVerifiedAgentVersion(t *testing.T) {
	dataDir := t.TempDir()
	versionsPath := filepath.Join(managed.HookGuardianAuthorizationDir(dataDir), managed.HookGuardianAgentVersionsFile)
	const versions = `{"version":1,"protected_targets":[
 {"user":"dcr-std1","uid":1001,"connector":"claudecode","ok":true,"result":{"agent_version":"2.1.323"}},
 {"user":"dcr-std1","uid":1001,"connector":"codex","ok":true,"result":{"agent_version":"0.168.0"}}]}`
	var record managedHookLedger
	if err := json.Unmarshal([]byte(versions), &record); err != nil {
		t.Fatal(err)
	}
	versionsErr := error(nil)
	previous := loadCallerAgentLedger
	loadCallerAgentLedger = func(path string) (managedHookLedger, error) {
		if path == versionsPath {
			return record, versionsErr
		}
		// The guardian ledger of a machine-policy host: no per-user rows.
		return managedHookLedger{}, nil
	}
	t.Cleanup(func() { loadCallerAgentLedger = previous })

	api := &APIServer{scannerCfg: &config.Config{DataDir: dataDir}}
	peer := func(uid int) context.Context {
		return withManagedHookPeer(context.Background(), managedHookPeer{UID: uid})
	}
	for _, name := range []string{"claudecode", "codex"} {
		machine := api.hookProfileForConnector(name)
		got := api.hookProfileForRequest(peer(1001), name)
		if got.AgentVersion == "" || got.CompatibilityStatus == connector.HookCompatibilityUnversioned ||
			strings.Contains(got.CompatibilityReason, "not probed") {
			t.Errorf("%s: profile version %q status %q reason %q, want the caller's verified version",
				name, got.AgentVersion, got.CompatibilityStatus, got.CompatibilityReason)
		}
		if got.ContractID != machine.ContractID {
			t.Errorf("%s: contract %q, want the machine-policy render's %q", name, got.ContractID, machine.ContractID)
		}
		if other := api.hookProfileForRequest(peer(1002), name); other.AgentVersion != machine.AgentVersion ||
			other.CompatibilityStatus != machine.CompatibilityStatus {
			t.Errorf("%s: a caller with no published version got %q %q, want the machine profile", name, other.AgentVersion, other.CompatibilityStatus)
		}
	}
	versionsErr = errors.New("agent versions record is not root-owned")
	if got, machine := api.hookProfileForRequest(peer(1001), "claudecode"), api.hookProfileForConnector("claudecode"); got.AgentVersion != machine.AgentVersion {
		t.Errorf("unreadable record: version %q, want the machine profile's %q", got.AgentVersion, machine.AgentVersion)
	}
}
