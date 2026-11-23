//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// rel-1-0-10 GAP-1713: the guardian's ensure pass rendered every recorded
// form of the Claude drop-in (each rendering checks the hook executables)
// under the managed policy transaction lock and held it 9-14 s, so Setup
// /uninstall, waiting 10 s for the same lock, failed 1603. The renderings are
// made before the lock; under it the drop-in is read and checked again.
func TestStandaloneClaudeEnsureRendersRecordedFormsOutsideTransactionLock(t *testing.T) {
	requireGAP633Elevated(t) // a standard user is refused the managed policy folder (rel-1-0-10 GAP-1519)
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
	// The direct-command form of the same contract and lock: a recorded
	// earlier form the ensure pass upgrades.
	var direct []byte
	for _, contract := range windowsClaudeRecordedPolicyContracts() {
		for _, lock := range []bool{true, false} {
			candidate, renderErr := renderWindowsClaudeRecordedPolicy(record, contract, lock)
			if renderErr != nil {
				t.Fatal(renderErr)
			}
			if direct == nil && bytes.Equal(candidate, current) {
				if direct, err = renderWindowsClaudeRecordedPolicy(record, contract, lock, windowsClaudeFormDirect); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	if direct == nil || bytes.Equal(direct, current) {
		t.Fatal("fixture has no distinct direct policy form")
	}
	directRecord := record
	directRecord.PolicySHA256 = windowsManagedPolicyDigest(direct)
	directState, err := json.MarshalIndent(directRecord, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	directState = append(directState, '\n')
	publishDirect := func() {
		t.Helper()
		if err := windowsManagedPolicyWriter(fixture.policyPath, direct, true); err != nil {
			t.Fatal(err)
		}
		if err := windowsManagedPolicyWriter(statePath, directState, true); err != nil {
			t.Fatal(err)
		}
	}

	transaction := windowsClaudeManagedPolicyTransaction
	render := windowsClaudeRecordedPolicyRender
	t.Cleanup(func() {
		windowsClaudeManagedPolicyTransaction = transaction
		windowsClaudeRecordedPolicyRender = render
	})
	locked := false
	var onLock func()
	windowsClaudeManagedPolicyTransaction = func(fn func() error) error {
		return transaction(func() error {
			locked = true
			defer func() { locked = false }()
			if onLock != nil {
				hook := onLock
				onLock = nil
				hook()
			}
			return fn()
		})
	}
	total, underLock := 0, 0
	windowsClaudeRecordedPolicyRender = func(
		record windowsClaudeManagedPolicyState,
		contract string,
		lock bool,
		form windowsClaudeRecordedForm,
	) ([]byte, error) {
		total++
		if locked {
			underLock++
		}
		return render(record, contract, lock, form)
	}
	ensure := connector.SetupOpts{APIAddr: opts.APIAddr, HookExecutable: fixture.hookExe}
	ensureOutsideLock := func(name string) {
		t.Helper()
		total, underLock = 0, 0
		if err := EnsureWindowsStandaloneClaudeManagedPolicy(ensure); err != nil {
			t.Fatalf("%s: ensure: %v", name, err)
		}
		if total == 0 {
			t.Fatalf("%s: ensure rendered no recorded Claude policy form", name)
		}
		if underLock != 0 {
			t.Fatalf("%s: ensure made %d of its %d recorded Claude policy renderings under the managed policy transaction lock", name, underLock, total)
		}
		got, err := os.ReadFile(fixture.policyPath)
		if err != nil || !bytes.Equal(got, current) {
			t.Fatalf("%s: ensure left a policy other than the current rendering: err=%v", name, err)
		}
	}

	// The published drop-in is current: nothing changes.
	ensureOutsideLock("current drop-in")
	// An earlier recorded form is upgraded.
	publishDirect()
	ensureOutsideLock("direct drop-in")

	// The drop-in changes between the unlocked read and the lock: the pass
	// works from what it reads under the lock, not from the earlier read.
	onLock = publishDirect
	if err := EnsureWindowsStandaloneClaudeManagedPolicy(ensure); err != nil {
		t.Fatalf("ensure after a concurrent change: %v", err)
	}
	got, err := os.ReadFile(fixture.policyPath)
	if err != nil || !bytes.Equal(got, current) {
		t.Fatalf("a drop-in changed before the lock was not upgraded from its locked read: err=%v", err)
	}
	gotState, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	var upgraded windowsClaudeManagedPolicyState
	if err := decodeWindowsClaudeManagedPolicyState(gotState, &upgraded); err != nil {
		t.Fatal(err)
	}
	if upgraded.PolicySHA256 != windowsManagedPolicyDigest(current) ||
		len(upgraded.TargetSIDs) != 1 || upgraded.TargetSIDs[0] != fixture.targetSID.String() {
		t.Fatalf("ownership record after the concurrent change: %+v", upgraded)
	}
}

// lockCountingClaudeProvider counts the drop-in checks made while the test's
// transaction wrapper holds the managed policy lock.
type lockCountingClaudeProvider struct {
	connector.ManagedHookPolicyProvider
	locked           *bool
	total, underLock *int
}

func (p lockCountingClaudeProvider) VerifyManagedHookPolicy(body []byte, setup connector.SetupOpts) error {
	*p.total++
	if *p.locked {
		*p.underLock++
	}
	return p.ManagedHookPolicyProvider.VerifyManagedHookPolicy(body, setup)
}

// rel-1-0-10 GAP-1713 (second holder): deferred staging proves the published
// Claude drop-in is this deployment's with VerifyWindowsClaudeManagedPolicyIdentity,
// which checked the bytes against every recorded contract, lock and guard
// form under the lock (5 s on the managed host, every pass). The bytes read
// under the lock are checked after it is released.
func TestClaudePolicyIdentityChecksTheDropInOutsideTransactionLock(t *testing.T) {
	requireGAP633Elevated(t) // a standard user is refused the managed policy folder (rel-1-0-10 GAP-1519)
	fixture := newWindowsManagedInstallFixture(t, map[string]interface{}{"allowManagedHooksOnly": true})
	setStandaloneProfileForTest(t, true)
	opts := windowsManagedInstallOptions(fixture)
	opts.AgentVersion = "2.1.230 (Claude Code)"
	if _, err := Install(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	transaction := windowsClaudeManagedPolicyTransaction
	provider := windowsClaudeManagedPolicyIdentityProvider
	t.Cleanup(func() {
		windowsClaudeManagedPolicyTransaction = transaction
		windowsClaudeManagedPolicyIdentityProvider = provider
	})
	locked := false
	total, underLock := 0, 0
	windowsClaudeManagedPolicyTransaction = func(fn func() error) error {
		return transaction(func() error {
			locked = true
			defer func() { locked = false }()
			return fn()
		})
	}
	windowsClaudeManagedPolicyIdentityProvider = func() connector.ManagedHookPolicyProvider {
		return lockCountingClaudeProvider{provider(), &locked, &total, &underLock}
	}
	if err := VerifyWindowsClaudeManagedPolicyIdentity(fixture.hookExe, opts.APIAddr, "DefenseClawGateway-Test"); err != nil {
		t.Fatalf("identity of the installed policy: %v", err)
	}
	if total == 0 {
		t.Fatal("the identity proof checked no drop-in bytes")
	}
	if underLock != 0 {
		t.Fatalf("the identity proof made %d of its %d drop-in checks under the managed policy transaction lock", underLock, total)
	}

	// A drop-in whose record authenticates it but that no recorded contract
	// renders is still refused, from the bytes read under the lock.
	statePath := filepath.Join(filepath.Dir(fixture.policyPath), windowsClaudeManagedStateFile)
	stateBody, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	var record windowsClaudeManagedPolicyState
	if err := decodeWindowsClaudeManagedPolicyState(stateBody, &record); err != nil {
		t.Fatal(err)
	}
	foreign := []byte("{\n  \"hooks\": {}\n}\n")
	record.PolicySHA256 = windowsManagedPolicyDigest(foreign)
	foreignState, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := windowsManagedPolicyWriter(fixture.policyPath, foreign, true); err != nil {
		t.Fatal(err)
	}
	if err := windowsManagedPolicyWriter(statePath, append(foreignState, '\n'), true); err != nil {
		t.Fatal(err)
	}
	if err := VerifyWindowsClaudeManagedPolicyIdentity(fixture.hookExe, opts.APIAddr, "DefenseClawGateway-Test"); err == nil {
		t.Fatal("the identity proof accepted a drop-in no recorded contract renders")
	}
}
