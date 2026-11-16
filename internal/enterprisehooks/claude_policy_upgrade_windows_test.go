//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

func TestStandaloneClaudeEnsureUpgradesAuthenticatedActiveDirectPolicy(t *testing.T) {
	fixture := newWindowsManagedInstallFixture(t, map[string]interface{}{"allowManagedHooksOnly": true})
	setStandaloneProfileForTest(t, true)
	opts := windowsManagedInstallOptions(fixture)
	opts.AgentVersion = "2.1.230 (Claude Code)"
	if _, err := Install(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	current, err := os.ReadFile(fixture.policyPath)
	if err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(filepath.Dir(fixture.policyPath), windowsClaudeManagedStateFile)
	stateBody, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	var record windowsClaudeManagedPolicyState
	if err := decodeWindowsClaudeManagedPolicyState(stateBody, &record); err != nil {
		t.Fatal(err)
	}
	var previous []byte
	for _, contract := range windowsClaudeRecordedPolicyContracts() {
		for _, lock := range []bool{true, false} {
			candidate, renderErr := renderWindowsClaudeRecordedPolicy(record, contract, lock)
			if renderErr != nil {
				t.Fatal(renderErr)
			}
			if bytes.Equal(candidate, current) {
				previous, err = renderWindowsClaudeRecordedPolicy(record, contract, lock, true)
				if err != nil {
					t.Fatal(err)
				}
				break
			}
		}
		if previous != nil {
			break
		}
	}
	if previous == nil || bytes.Equal(previous, current) {
		t.Fatal("fixture has no distinct earlier direct policy form")
	}
	record.PolicySHA256 = windowsManagedPolicyDigest(previous)
	stateBody, err = json.MarshalIndent(record, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	stateBody = append(stateBody, '\n')
	if err := windowsManagedPolicyWriter(fixture.policyPath, previous, true); err != nil {
		t.Fatal(err)
	}
	if err := windowsManagedPolicyWriter(statePath, stateBody, true); err != nil {
		t.Fatal(err)
	}
	if err := VerifyWindowsClaudeManagedPolicyIdentity(fixture.hookExe, opts.APIAddr, "DefenseClawGateway-Test"); err != nil {
		t.Fatalf("authenticated earlier policy identity: %v", err)
	}

	// No target install runs here; the existing enrolled account can be signed out.
	ensure := connector.SetupOpts{APIAddr: opts.APIAddr, HookExecutable: fixture.hookExe}
	writer := windowsManagedPolicyWriter
	t.Cleanup(func() { windowsManagedPolicyWriter = writer })
	failStateOnce := true
	windowsManagedPolicyWriter = func(path string, data []byte, sensitive bool) error {
		if path == statePath && failStateOnce {
			failStateOnce = false
			return errors.New("test state write refusal")
		}
		return writer(path, data, sensitive)
	}
	if err := EnsureWindowsStandaloneClaudeManagedPolicy(ensure); err == nil {
		t.Fatal("upgrade accepted an incomplete policy and ownership record")
	}
	windowsManagedPolicyWriter = writer
	rolledBackPolicy, err := os.ReadFile(fixture.policyPath)
	if err != nil || !bytes.Equal(rolledBackPolicy, previous) {
		t.Fatalf("policy rollback changed the earlier body: err=%v", err)
	}
	rolledBackState, err := os.ReadFile(statePath)
	if err != nil || !bytes.Equal(rolledBackState, stateBody) {
		t.Fatalf("ownership rollback changed the earlier record: err=%v", err)
	}
	if err := EnsureWindowsStandaloneClaudeManagedPolicy(ensure); err != nil {
		t.Fatalf("ensure active policy: %v", err)
	}
	got, err := os.ReadFile(fixture.policyPath)
	if err != nil || !bytes.Equal(got, current) {
		t.Fatalf("upgraded policy differs from its prior contract: err=%v", err)
	}
	targets, active, err := ReadWindowsClaudeManagedPolicyTargets()
	if err != nil || !active || len(targets) != 1 || targets[0] != fixture.targetSID.String() {
		t.Fatalf("enrolled targets changed: active=%t targets=%v err=%v", active, targets, err)
	}
	if err := EnsureWindowsStandaloneClaudeManagedPolicy(ensure); err != nil {
		t.Fatalf("idempotent ensure: %v", err)
	}
	again, err := os.ReadFile(fixture.policyPath)
	if err != nil || !bytes.Equal(again, current) {
		t.Fatalf("current policy changed on repeated ensure: err=%v", err)
	}
}
